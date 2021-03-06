// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// Copyright 2022 Anders Håål

package main

import "github.com/gomodule/redigo/redis"

type AllConfig struct {
	AllGraphs       map[string]map[string][]interface{}
	NodeFields      map[string]map[string]string
	EdgeFields      map[string]map[string]string
	RedisConnection RedisConnection
	RedisPool       *redis.Pool
}

type RedisConnection struct {
	Host      string //`mapstructure:"host"`
	Port      string //`mapstructure:"port"`
	DB        string //`mapstructure:"db"`
	MaxActive int    //`mapstructure:"max_active"`
	MaxIdle   int    //`mapstructure:"max_idle"`
}

type Field struct {
	FieldName string `mapstructure:"field_name"`
	Type      string `mapstructure:"type"`
}
