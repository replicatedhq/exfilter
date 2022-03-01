package post2db

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/exfilter/exfilter/pkg/exfilterlogger"
)

func PostEvent(event exfilterlogger.EgressEvent, restapiurl string) error {
	b, err := json.Marshal(event)
	if err != nil {
		fmt.Println(err)
		return err
	}

	postBody := bytes.NewBuffer(b)
	fmt.Println("postbody:", postBody)
	resp, err := http.Post(restapiurl, "application/json", postBody)
	fmt.Println(resp)
	if err != nil {
		log.Printf("Request Failed: %s", err)
		return err
	}
	defer resp.Body.Close()
	return nil
}
