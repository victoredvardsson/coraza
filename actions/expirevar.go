// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package actions

import (
	"fmt"
	"strconv"
	"strings"

	engine "github.com/jptosso/coraza-waf/v1"
	_ "github.com/jptosso/coraza-waf/v1/utils"
)

type Expirevar struct {
	collection string
	ttl        int
	key        string
}

func (a *Expirevar) Init(r *engine.Rule, data string) error {
	spl := strings.SplitN(data, "=", 2)
	a.ttl, _ = strconv.Atoi(spl[1])
	spl = strings.SplitN(spl[0], ".", 2)
	if len(spl) != 2 {
		return fmt.Errorf("Expirevar must contain key=value")
	}
	a.collection = spl[0]
	a.key = spl[1]
	return nil
}

func (a *Expirevar) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	// Not implemented
}

func (a *Expirevar) GetType() int {
	return engine.ACTION_TYPE_NONDISRUPTIVE
}