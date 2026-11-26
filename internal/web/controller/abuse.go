package controller

import (
	"fmt"
	"strconv"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"

	"github.com/gin-gonic/gin"
)

type abuseBanRequest struct {
	IP string `json:"ip" binding:"required"`
}

type abuseSettingsRequest struct {
	Enabled bool `json:"enabled"`
}

func registerAbuseRoutes(api *gin.RouterGroup) {
	abuse := api.Group("/abuse")
	abuse.GET("/settings", func(c *gin.Context) {
		s := &service.SettingService{}
		logEnabled, err := s.GetAccessLogEnable()
		if err != nil {
			jsonObj(c, nil, err)
			return
		}
		enabled, err := s.GetAbuseStatsEnable()
		jsonObj(c, gin.H{"logEnabled": logEnabled, "enabled": enabled}, err)
	})
	abuse.POST("/settings", func(c *gin.Context) {
		var input abuseSettingsRequest
		if err := c.ShouldBindJSON(&input); err != nil {
			jsonObj(c, nil, err)
			return
		}
		err := (&service.SettingService{}).SetAbuseStatsEnable(input.Enabled)
		jsonObj(c, nil, err)
	})
	abuse.GET("/summary", func(c *gin.Context) {
		hours := 24
		if raw := c.Query("hours"); raw != "" {
			var err error
			hours, err = strconv.Atoi(raw)
			if err != nil {
				jsonObj(c, nil, fmt.Errorf("invalid time window"))
				return
			}
		}
		result, err := service.GetAbuseSummary(hours)
		jsonObj(c, result, err)
	})
	abuse.GET("/bandwidth", func(c *gin.Context) {
		result, err := service.GetAbuseBandwidth(c.Query("email"))
		jsonObj(c, result, err)
	})
	abuse.GET("/bans", func(c *gin.Context) {
		result, err := service.GetAbuseBans()
		jsonObj(c, result, err)
	})
	abuse.POST("/ban", func(c *gin.Context) {
		var input abuseBanRequest
		if err := c.ShouldBindJSON(&input); err != nil {
			jsonObj(c, nil, fmt.Errorf("invalid IP address"))
			return
		}
		err := service.SetAbuseBan(input.IP, true)
		if err == nil {
			logger.Infof("Abuse panel: banned source IP %s", input.IP)
		}
		jsonObj(c, nil, err)
	})
	abuse.POST("/unban", func(c *gin.Context) {
		var input abuseBanRequest
		if err := c.ShouldBindJSON(&input); err != nil {
			jsonObj(c, nil, fmt.Errorf("invalid IP address"))
			return
		}
		err := service.SetAbuseBan(input.IP, false)
		if err == nil {
			logger.Infof("Abuse panel: unbanned source IP %s", input.IP)
		}
		jsonObj(c, nil, err)
	})
}
