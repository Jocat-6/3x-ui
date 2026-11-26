package service

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const abuseJail = "3x-ipl"

type AbuseBans struct {
	Available bool     `json:"available"`
	Jail      string   `json:"jail"`
	IPs       []string `json:"ips"`
}

func validAbuseIP(value string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("enter a single IP address")
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return "", fmt.Errorf("only public source IP addresses can be managed")
	}
	return addr.String(), nil
}

func runAbuseFail2ban(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "fail2ban-client", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("fail2ban unavailable or command failed: %w", err)
	}
	return string(output), nil
}

func GetAbuseBans() (*AbuseBans, error) {
	result := &AbuseBans{Jail: abuseJail, IPs: []string{}}
	if runtime.GOOS == "windows" {
		return result, nil
	}
	output, err := runAbuseFail2ban("status", abuseJail)
	if err != nil {
		return result, nil
	}
	result.Available = true
	for _, line := range strings.Split(output, "\n") {
		if _, tail, ok := strings.Cut(line, "Banned IP list:"); ok {
			for _, value := range strings.Fields(tail) {
				if ip, err := validAbuseIP(value); err == nil {
					result.IPs = append(result.IPs, ip)
				}
			}
			break
		}
	}
	return result, nil
}

func SetAbuseBan(value string, ban bool) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("fail2ban is unavailable on Windows")
	}
	ip, err := validAbuseIP(value)
	if err != nil {
		return err
	}
	action := "unbanip"
	if ban {
		action = "banip"
	}
	_, err = runAbuseFail2ban("set", abuseJail, action, ip)
	return err
}
