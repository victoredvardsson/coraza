package engine

import(
	pcre"github.com/gijsbers/go-pcre"
	"sync"
	"strings"
	"fmt"
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

type Collection struct{
	Name string
	Key string
}

type LocalCollection struct {
	Data map[string][]string `json:"data"`
	mux *sync.RWMutex
	Name string
}

func NewCollection(name string) *LocalCollection{
	col := &LocalCollection{}
	col.Init(name)
	return col
}

func (c *LocalCollection) Init(name string) {
	c.Data = map[string][]string{}
	c.Data[""] = []string{}
	c.mux = &sync.RWMutex{}
	c.Name = name
}

func (c *LocalCollection) InitCollection(key string) {
	c.Data[key] = []string{}
}

//PCRE compatible collection
func (c *LocalCollection) Get(key string) []string{
	//we return every value in case there is no key but there is a collection
	if len(key) == 0{
		data := []string{}
		// how does modsecurity solves this?
		for k := range c.Data{
			for _, v := range c.Data[k]{
				//val := k + "=" + n
				data = append(data, v)
			}
		}
		return data
	}
	if key[0] == '/'{
		key = utils.TrimLeftChars(key, 1)
		key = strings.TrimSuffix(key, string('/'))
		re := pcre.MustCompile(key, 0)
		result := []string{}
		for k := range c.Data {
		    m := re.Matcher([]byte(k), 0)
		    if m.Matches(){
		    	for _, d := range c.Data[k]{
		    		result = append(result, d)
		    	}
		    }
		}
		return result
	}else{
		return c.Data[key]
	}
}

//PCRE compatible collection
func (c *LocalCollection) GetWithExceptions(key string, exceptions []string) []*MatchData{
	//we return every value in case there is no key but there is a collection
	if len(key) == 0{
		data := []*MatchData{}
		for k := range c.Data{
			if utils.ArrayContains(exceptions, k){
				continue
			}
			for _, v := range c.Data[k]{
				//val := k + "=" + n
				data = append(data, &MatchData{
					Collection: c.Name,
					Value: v,
					Key: k,
				})
			}
		}
		return data
	}

	if key[0] == '/'{
		key = utils.TrimLeftChars(key, 1)
		key = strings.TrimSuffix(key, string('/'))
		re := pcre.MustCompile(key, 0)
		result := []*MatchData{}
		for k := range c.Data {
			if utils.ArrayContains(exceptions, k){
				continue
			}
		    m := re.Matcher([]byte(k), 0)
		    if m.Matches(){
		    	for _, d := range c.Data[k]{
		    		result = append(result, &MatchData{
		    			Collection: c.Name,
		    			Key: k,
		    			Value: d,
		    		})
		    	}
		    }
		}
		return result
	}else{
		ret := []*MatchData{}
		//We pass through every record to apply filters
		for k := range c.Data{
			if utils.ArrayContains(exceptions, k){
				continue
			}
			if k == key{
				for _, kd := range c.Data[k]{
					ret = append(ret, &MatchData{
		    			Collection: c.Name,
		    			Key: k,
		    			Value: kd,
		    		})
				}
			}
		}
		return ret
	}
}

func (c *LocalCollection) GetFirstString() string{
	a := c.Data[""]
	if len(a) > 0{
		return a[0]
	}else{
		return ""
	}
}

func (c *LocalCollection) GetFirstInt64() int64{
	a := c.Data[""]
	if len(a) > 0{
		i, _ := strconv.ParseInt(a[0], 10, 64)
		return i
	}else{
		return 0
	}
}

func (c *LocalCollection) GetFirstInt() int{
	a := c.Data[""]
	if len(a) > 0{
		i, _ := strconv.Atoi(a[0])
		return i
	}else{
		return 0
	}
}

func (c *LocalCollection) Concat() []string{
	r := []string{}
	for k, v := range c.Data{
		r = append(r, fmt.Sprintf("%s=%s", k, v))
	}
	return r
}

func (c *LocalCollection) Add(key string, value []string) {
	c.Data[key] = value
}

func (c *LocalCollection) AddToKey(key string, value string) {
	c.Data[key] = append(c.Data[key], value)
}


func (c *LocalCollection) Set(key string, value []string) {
	c.Data[key] = value
}

func (c *LocalCollection) AddMap(data map[string][]string) {
	for k, v := range data{
		c.Data[strings.ToLower(k)] = v
	}
}

func (c *LocalCollection) Update(key string, value []string) {
	c.Data[key] = value
}

func (c *LocalCollection) Remove(key string) {
	delete(c.Data, key)
}

func (c *LocalCollection) Flush(key string) {
	//not implemented
}

func (c *LocalCollection) GetData() map[string][]string {
	return c.Data
}