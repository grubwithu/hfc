package analysis

import "container/list"

type CDF struct {
	Values list.List
}

func (cdf *CDF) Add(value float64) {
	if cdf.Values.Len() == 0 {
		cdf.Values.PushBack(value)
	} else {
		for e := cdf.Values.Front(); e != nil; e = e.Next() {
			if value < e.Value.(float64) {
				cdf.Values.InsertBefore(value, e)
				return
			}
		}
		cdf.Values.PushBack(value)
	}
}

func (cdf *CDF) GetCDFValue(value float64) float64 {
	if cdf.Values.Len() == 0 {
		return 0
	}
	index := 0
	for e := cdf.Values.Front(); e != nil; e = e.Next() {
		if value < e.Value.(float64) {
			return float64(index) / float64(cdf.Values.Len())
		}
		index++
	}
	return 1
}
