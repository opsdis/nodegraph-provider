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
// Copyright 2020 Opsdis AB

package main
type AllConfig struct {
	AllNodeFields	[]interface{}
	AllEdgeFields	[]interface{}
}
type NodeFields []*NodeField


type NodeField struct {
	FieldName            string         `mapstructure:"field_name" json:"field_name"`
}


type Nodes []*Node

type Node struct {
	Id            string         `mapstructure:"id"`
	Title         string         `mapstructure:"title"`
	SubTitle      string         `mapstructure:"subTitle"`
	MainStat      string         `mapstructure:"mainStat"`
	SecondaryStat string         `mapstructure:"secondaryStat"`
	Detail        []StaticLabels `string:"detail"`
	Arc           []StaticLabels `string:"arc"`
	Queries       []Query        `string:"queries"`
}


type StaticLabels struct {
	Key   string `mapstructure:"key"`
	Value string `mapstructure:"value"`
}

// Define a Query config
type Query struct {
	Id    string `mapstructure:"id"`
	Query string `mapstructure:"query"`
}
