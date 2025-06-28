// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package db

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"parser-app/entities"
	"strconv"
	//    _ "github.com/go-sql-Driver/mysql"
)

type Driver string

const (
	DriverSqlite   Driver = "sqlite3"
	DriverPostgres Driver = "postgres"
	DriverMysql    Driver = "mysql"
)

type ConnAttrs struct {
	Host     string
	Port     int
	User     string
	Password string
	DbName   string
	Driver   Driver
	Schema   string
}
type Connection interface {
	GetPrepareStatement(stmtSQL string) (*sql.Stmt, error)
	GetScalarValue(sqlStmt string, params []interface{}) (interface{}, error)
	Execute(sqlStmt string, params []interface{}) error
	GetHeaderId(key, value string) (string, error)
	GetPeerId(src entities.EndPoint, dst entities.EndPoint, serviceName, captureId string) (int, error)
	GetPacketId(packet entities.ParsedPacket, captureId string) (int, error)
	SetPacketHeaders(packetId int, headers []string) error
}
type connection struct {
	db         *sql.DB
	err        error
	statements map[string]*sql.Stmt
}

func MakeConnection(conn ConnAttrs) (Connection, error) {
	db := connection{
		db:         nil,
		err:        nil,
		statements: nil,
	}
	switch conn.Driver {
	case DriverSqlite:
		{
			connectionString := fmt.Sprintf("file:%s", conn.DbName)
			db.db, db.err = sql.Open(string(conn.Driver), connectionString)
			if db.err == nil {
				db.statements = make(map[string]*sql.Stmt)
			}
		}
	case DriverPostgres:
		{
			connectionString := fmt.Sprintf("Host=%s Port=%d User=%s Password=%s DbName=%s sslmode=disable",
				conn.Host, conn.Port, conn.User, conn.Password, conn.DbName)
			db.db, db.err = sql.Open(string(conn.Driver), connectionString)
			if db.err == nil {
				db.statements = make(map[string]*sql.Stmt)
			}
		}
	case DriverMysql:
		{
			connectionString := fmt.Sprintf("%s:%s@%s:%d/%s",
				conn.User, conn.Password, conn.Host, conn.Port, conn.DbName)
			db.db, db.err = sql.Open(string(conn.Driver), connectionString)
		}
	default:
		db.err = fmt.Errorf("driver %s not supported", conn.Driver)
	}
	if db.err == nil {
		db.statements = make(map[string]*sql.Stmt)
		return &db, db.err
	}
	return nil, fmt.Errorf("unknown Driver %s", conn.Driver)
}

func (pg *connection) GetPrepareStatement(stmtSQL string) (*sql.Stmt, error) {
	if val, ok := (*pg).statements[stmtSQL]; ok {
		return val, nil
	}
	stmt, err := (*pg).db.Prepare(stmtSQL)
	if err == nil {
		(*pg).statements[stmtSQL] = stmt
	}
	return stmt, err
}

func (pg *connection) GetScalarValue(sqlStmt string, params []interface{}) (interface{}, error) {
	stmt, err := pg.GetPrepareStatement(sqlStmt)
	if err != nil {
		return -1, err
	}
	var (
		id interface{}
	)
	if len(params) == 0 {
		err = stmt.QueryRow().Scan(&id)
	} else if len(params) == 1 {
		err = stmt.QueryRow(params[0]).Scan(&id)
	} else if len(params) > 1 {
		err = stmt.QueryRow(params...).Scan(&id)
	}
	return id, err
}

func (pg *connection) Execute(sqlStmt string, params []interface{}) error {
	stmt, err := pg.GetPrepareStatement(sqlStmt)
	if err != nil {
		return err
	}
	if len(params) == 0 {
		_, err = stmt.Exec()
	} else if len(params) == 1 {
		_, err = stmt.Exec(params[0])
	} else if len(params) > 1 {
		_, err = stmt.Exec(params...)
	}
	return err
}

func (pg *connection) GetHeaderId(key, value string) (string, error) {
	params := make([]interface{}, 2)
	params[0] = key
	params[1] = value
	id, err := pg.GetScalarValue("SELECT Header_Id FROM HTTP_Headers where Name=$1 and Value=$2", params)
	if err != nil {
		id = entities.ComputeId(key, value)
		params = append(params, id)
		err = pg.Execute("INSERT INTO HTTP_Headers(Name, Value, Header_Id) VALUES($1, $2, $3)", params)
		log.Printf("Inserted header. name %v, value:%v, id %v", params[0], params[1], params[2])
	}
	return fmt.Sprint(id), err
}

func (pg *connection) GetPeerId(src entities.EndPoint, dst entities.EndPoint, serviceName, captureId string) (int, error) {
	var (
		idv interface{}
		err error = nil
	)
	params := make([]interface{}, 6)
	params[0] = src.Address
	params[1] = src.Port
	params[2] = dst.Address
	params[3] = dst.Port
	params[4] = serviceName
	params[5] = captureId
	for i := 0; i < 2; i++ {
		idv, err = pg.GetScalarValue("SELECT Peer_Id FROM IP_peers where Source_Ip=$1 and Source_Port=$2 and Dest_Ip=$3 and Dest_port=$4 and ServiceName=$5 and  capture_id=$6", params)
		if err != nil {
			if i == 0 {
				err = pg.Execute("INSERT INTO IP_peers(Source_Ip, Source_Port, Dest_Ip, Dest_port, ServiceName, capture_id) VALUES($1, $2, $3, $4, $5, $6)", params)
				if err != nil {
					return -2, err
				}
			} else {
				return -1, err
			}
		} else {
			id, err := VarToInt(idv)
			if err == nil {
				return id, nil
			} else {
				err = fmt.Errorf("unable to convert returned peer_id value '%v' to int. Error: %v", idv, err)
			}
			break
		}
	}
	return -3, fmt.Errorf("attempts exhausted")
}

func (pg *connection) GetPacketId(packet entities.ParsedPacket, captureId string) (int, error) {
	var idv interface{}
	peerId, err := pg.GetPeerId(packet.Peers[0], packet.Peers[1], packet.ServiceName, captureId)
	if err != nil {
		return -1, fmt.Errorf("unable to acquire peer id")
	}
	params := make([]interface{}, 6)
	params[0] = peerId
	params[1] = packet.SeqNo
	params[2] = packet.AckNo
	params[3] = packet.Timestamp.Unix()
	params[4] = packet.StrPayload
	params[5] = captureId
	for i := 0; i < 2; i++ {
		idv, err = pg.GetScalarValue("SELECT Packet_id FROM Packets where Peer_id=$1 and Seq_No=$2 and Ack_no=$3 and Time_Stamp=$4 and Body=$5 and capture_id=$6", params)
		if err != nil {
			if i == 0 {
				err = pg.Execute("INSERT INTO Packets(Peer_id, Seq_No, Ack_no, Time_Stamp, Body, capture_id) VALUES($1, $2, $3, $4, $5, $6)", params)
				if err != nil {
					return -2, err
				}
			} else {
				return -1, err
			}
		} else {
			id, err := VarToInt(idv)
			if err == nil {
				return id, err
			} else {
				err = fmt.Errorf("unable to convert returned packet_id value '%v' to int (%v)", idv, err)
			}
			break
		}
	}
	return -3, fmt.Errorf("attempts exhausted")
}

func (pg *connection) SetPacketHeaders(packetId int, headers []string) error {
	params := make([]interface{}, 1)
	params[0] = packetId
	err := pg.Execute("delete from Packet_headers where Packet_Id=$1", params)
	if err != nil {
		return err
	}
	if len(headers) > 0 {
		params = append(params, headers[0])
	}
	for _, h := range headers {
		params[1] = h
		err := pg.Execute("INSERT INTO Packet_headers(packet_id, header_id) VALUES ($1, $2)", params)
		if err != nil {
			return fmt.Errorf("unable to insert packet header for %v/%v. Error: %v", params[0], params[1], err)
		}
	}
	return nil
}

func VarToInt(idv interface{}) (int, error) {
	s1 := fmt.Sprintf("%v", idv)
	s2, err := strconv.Atoi(s1)
	if err != nil {
		log.Errorf("unable to convert returned value '%v' to int: %v", idv, err)
		return -2, err
	}
	return s2, nil
}
