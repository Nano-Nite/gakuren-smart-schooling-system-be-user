package db

import (
	"log"

	"github.com/jackc/pgx/v5"
)

func GetSingleDataByQuery[T any](query string, param ...interface{}) (*T, error) {
	rows, err := Conn.Query(DBCtx, query, param...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	result, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[T])
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	return &result, nil
}
