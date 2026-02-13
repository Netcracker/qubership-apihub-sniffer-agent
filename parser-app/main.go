package main

import (
	"flag"
	"fmt"
	"parser-app/Cache"
	"parser-app/db"
	"parser-app/readers"
)

func main() {
	var (
		workDir    string
		captureId  string
		connAttrs  db.ConnAttrs
		driverName string
	)
	flag.StringVar(&captureId, "capture-id", "", "Capturing ID to aggregate")
	flag.StringVar(&workDir, "work-dir", "", "Working directory")
	flag.StringVar(&connAttrs.Host, "host", "", "DB server host")
	flag.StringVar(&connAttrs.DbName, "instance", "", "DB instance name")
	flag.StringVar(&connAttrs.Password, "password", "", "DB user password")
	flag.StringVar(&connAttrs.User, "user", "", "DB user name")
	flag.StringVar(&connAttrs.Schema, "schema", "", "DB schema name")
	flag.IntVar(&connAttrs.Port, "port", 5432, "DB server port")
	flag.StringVar(&driverName, "driver", string(db.DriverSqlite), "DB driver name")
	flag.Parse()
	if captureId == "" || workDir == "" {
		panic("Missing capture ID and/or working directory")
	}
	connAttrs.Driver = db.Driver(driverName)
	if connAttrs.Driver == db.DriverSqlite {
		if connAttrs.DbName == "" {
			panic("Please provide database name for sqlite")
		}
	} else {
		if !(connAttrs.DbName != "" && connAttrs.Host != "" && connAttrs.Port > 0) {
			panic("Please provide mandatory parameters (host, port, instance ) for " + driverName)
		}
	}
	conn, err := db.MakeConnection(connAttrs)
	if err != nil {
		panic(err)
	}
	headers := Cache.NewHttpHeadersCache(conn)
	pis := Cache.NewPacketCache(captureId, conn)
	if pis == nil {
		fmt.Println("Unable to create packet storage")
		return
	}
	peerCache := Cache.NewPeersCache(captureId, conn)
	captureReader := readers.NewCaptureReader(headers, pis, peerCache)
	err = captureReader.ReadCapture(captureId, workDir)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Storage contains %d packets\n", pis.GetPacketCount())
}
