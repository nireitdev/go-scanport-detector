package main

import (
	"context"
	"fmt"
	"github.com/nireitdev/go-nmap-scans-detector/config"
	"github.com/nireitdev/go-nmap-scans-detector/db"
	"github.com/nireitdev/go-nmap-scans-detector/traffic"
	"log"
	"os"
	"strconv"
)

// Global vars
var (
	//remoteips = make(map[string]*remoteIP)
	//mu        sync.Mutex
	cfg   *config.Config
	redis db.Redis
	ctx   context.Context
)

func main() {
	ctx = context.Background()

	//cargo config:
	cfg = config.ReadConfig()
	hostname, err := os.Hostname()
	if err != nil {
		log.Println(err)
	}

	//Inicio conexion Redis:
	redis = db.Redis{Addr: cfg.Redis.Addr,
		User:     cfg.Redis.User,
		Password: cfg.Redis.Pass,
	}
	redis.Open(ctx)
	defer redis.Close()
	err = redis.Publish("INIT SERVER NRO " + strconv.Itoa(int(redis.NroServer)) + " host = " + hostname)
	if err != nil {
		log.Fatalf("Error tratando de publicar", err)
	}

	//Captura de trafico:
	captures := traffic.NewCapture(traffic.ConfigPcap{
		Ctx:        ctx,
		Device:     cfg.Config.Device,
		Ip:         cfg.Config.Ip,
		Portrange:  cfg.Config.Portrange,
		Portignore: cfg.Config.Portignore,
	})

	for cap := range captures {
		msg := fmt.Sprintf("SrcIP: %s  Proto: %s  PortLocal: %s ", cap.IPorigin, cap.Proto, cap.Portlocal)
		log.Printf(msg)
		redis.Publish(msg)
	}
}
