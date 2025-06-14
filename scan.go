package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type IPTestResult struct {
	IP             string
	AverageDelayMs float64
}

func main() {
	targetURLPtr := flag.String("u", "", "**必需** 目标URL，例如: https://xx.xx.xx")
	concurrentLimitPtr := flag.Int("c", 5, "并发限制数，默认: 5")
	ipFilePtr := flag.String("f", "ip.txt", "包含IP地址的文件路径，默认: ip.txt")
	outputFilePtr := flag.String("o", "info.txt", "输出结果的文件路径，默认: info.txt")

	flag.Parse()

	targetURL := *targetURLPtr
	concurrentLimit := *concurrentLimitPtr
	ipFile := *ipFilePtr
	outputFile := *outputFilePtr

	if targetURL == "" {
		fmt.Println("错误：请通过 -u 参数指定目标 URL。")
		fmt.Println("示例用法：")
		fmt.Println("  ./scan -u https://xx.xx.xx -c 5")
		flag.Usage()
		return
	}

	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/555.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/555.36"
	httpTimeout := 5 * time.Second

	ips, err := readIPsFromFile(ipFile)
	if err != nil {
		fmt.Printf("读取IP文件失败: %v\n", err)
		return
	}

	if len(ips) == 0 {
		fmt.Println("IP文件没有有效的IP地址，请检查 ip.txt 文件。")
		return
	}

	var (
		successful200ResultsMux sync.Mutex
		successful200Results    []IPTestResult
		wg                      sync.WaitGroup
		sem                     = make(chan struct{}, concurrentLimit)
		processedCountMux       sync.Mutex
		processedCount          int
	)

	totalIPs := len(ips)
	fmt.Printf("开始测试 %d 个IP，并发限制为 %d...\n", totalIPs, concurrentLimit)

	for i, ip := range ips {
		sem <- struct{}{}

		wg.Add(1)
		go func(index int, currentIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			processedCountMux.Lock()
			processedCount++
			currentProcessed := processedCount
			processedCountMux.Unlock()

			fmt.Printf("\r正在测试第 %d/%d 个IP: %s...", currentProcessed, totalIPs, currentIP)

			statusCode, httpErr := getWithForcedTargetIPAndHostHeader(targetURL, currentIP, userAgent, httpTimeout)
			if httpErr != nil {
				return
			}

			if statusCode == 200 {
				_, portStr, err := net.SplitHostPort(strings.Split(targetURL, "//")[1])
				if err != nil {
					if strings.HasPrefix(targetURL, "https://") {
						portStr = "443"
					} else if strings.HasPrefix(targetURL, "http://") {
						portStr = "80"
					} else {
						return
					}
				}

				delay, testErr := testTCPDialDelay(currentIP, portStr, 5)
				if testErr != nil {
				} else {
					delayMs := float64(delay) / float64(time.Millisecond)

					successful200ResultsMux.Lock()
					successful200Results = append(successful200Results, IPTestResult{
						IP:             currentIP,
						AverageDelayMs: delayMs,
					})
					successful200ResultsMux.Unlock()
				}
			}
		}(i+1, ip)
	}

	wg.Wait()
	fmt.Println("\n所有IP测试完成。")

	sort.Slice(successful200Results, func(i, j int) bool {
		return successful200Results[i].AverageDelayMs < successful200Results[j].AverageDelayMs
	})

	topResultsCount := 10
	if len(successful200Results) < topResultsCount {
		topResultsCount = len(successful200Results)
	}
	topResults := successful200Results[:topResultsCount]

	var linesToWrite []string
	if len(topResults) == 0 {
		linesToWrite = append(linesToWrite, "没有找到状态码为200的IP地址。")
	} else {
		for _, res := range topResults {
			linesToWrite = append(linesToWrite, fmt.Sprintf("%s----%.2f ms", res.IP, res.AverageDelayMs))
		}
	}

	err = writeResultsToFile(outputFile, linesToWrite)
	if err != nil {
		fmt.Printf("写入结果到文件失败: %v\n", err)
	} else {
		fmt.Printf("延迟最低的前%d个状态码为200的IP测试结果已写入到文件: %s\n", len(linesToWrite), outputFile)
	}
}

func getWithForcedTargetIPAndHostHeader(url string, forcedTargetIP string, userAgent string, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}
			_, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("解析目标地址失败: %w", err)
			}

			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("解析端口失败: %w", err)
			}

			remoteAddr := net.TCPAddr{IP: net.ParseIP(forcedTargetIP), Port: port}
			if remoteAddr.IP == nil {
				return nil, fmt.Errorf("无效的强制目标IP: %s", forcedTargetIP)
			}

			conn, err := dialer.DialContext(ctx, "tcp", remoteAddr.String())
			if err != nil {
				return nil, fmt.Errorf("拨号连接失败: %w", err)
			}
			return conn, nil
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName: extractHostFromURL(url),
		},
	}

	client := &http.Client{Transport: tr, Timeout: timeout}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Host = extractHostFromURL(url)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("读取响应体失败: %w", err)
	}

	return resp.StatusCode, nil
}

func testTCPDialDelay(ip string, port string, count int) (time.Duration, error) {
	totalDelay := time.Duration(0)
	target := net.JoinHostPort(ip, port)
	timeout := 3 * time.Second

	successfulTests := 0
	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		conn.Close()

		elapsed := time.Since(start)
		totalDelay += elapsed
		successfulTests++
		time.Sleep(100 * time.Millisecond)
	}

	if successfulTests == 0 {
		return 0, fmt.Errorf("所有TCP延迟测试均失败或无有效结果")
	}

	averageDelay := totalDelay / time.Duration(successfulTests)
	return averageDelay, nil
}

func extractHostFromURL(rawURL string) string {
	parts := strings.Split(rawURL, "//")
	if len(parts) < 2 {
		return rawURL
	}
	hostPort := parts[1]
	host := strings.Split(hostPort, "/")[0]
	host = strings.Split(host, ":")[0]
	return host
}

func readIPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("打开IP文件失败: %w", err)
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			ips = append(ips, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取IP文件内容失败: %w", err)
	}

	return ips, nil
}

func writeResultsToFile(filename string, results []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range results {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("写入行到文件失败: %w", err)
		}
	}
	return writer.Flush()
}