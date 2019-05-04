/*
Copyright 2019 Tom Peters

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pwned

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// PwnedPasswordAPI is the URL for the pwned passwords API
var PwnedPasswordAPI = "https://api.pwnedpasswords.com/range"

// Client is an http client with a default timeout of one second
var Client = &http.Client{
	Timeout: time.Second,
}

// ErrInvalidResponse is an error when we cannot comprehend the API response
var ErrInvalidResponse = errors.New("error: invalid response detected from pwnedpasswords.com")

func init() {
	if api := os.Getenv("PWNED_API"); api != "" {
		PwnedPasswordAPI = api
	}
}

// Count returns the number of times the password has been pwned
func Count(password string) (int, error) {
	sha := sha1.Sum([]byte(password))
	shaHex := hex.EncodeToString(sha[:])

	prefixBytes, suffixBytes := shaHex[0:5], shaHex[5:]
	suffix := strings.ToUpper(string(suffixBytes))

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s", PwnedPasswordAPI, prefixBytes), nil)
	if err != nil {
		return 0, err
	}

	res, err := Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), ":")
		if len(line) != 2 {
			return 0, ErrInvalidResponse
		}

		pwHex := strings.ToUpper(line[0])
		count, _ := strconv.Atoi(line[1])

		if pwHex == suffix {
			return count, nil
		}
	}

	return 0, nil
}
