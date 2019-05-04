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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/onsi/gomega"
)

func server(g *gomega.GomegaWithT, file string) *httptest.Server {
	resData, err := ioutil.ReadFile("testdata/" + file)
	if err != nil {
		panic(err)
	}

	h := func(w http.ResponseWriter, r *http.Request) {
		g.Expect(r.URL.Path).Should(gomega.Equal("/a94a8"))

		w.Header().Set("Content-Type", "text/plain")
		w.Write(resData)
	}

	return httptest.NewServer(http.HandlerFunc(h))
}

func TestCount(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	ts := server(g, "valid.txt")
	defer ts.Close()

	PwnedPasswordAPI = ts.URL
	count, err := Count("test")
	g.Expect(count).Should(gomega.Equal(74831))
	g.Expect(err).Should(gomega.Succeed())
}

func TestCountNotFound(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	ts := server(g, "not-found.txt")
	defer ts.Close()

	PwnedPasswordAPI = ts.URL
	count, err := Count("test")
	g.Expect(count).Should(gomega.Equal(0))
	g.Expect(err).Should(gomega.Succeed())
}

func TestCountInvalidResponse(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	ts := server(g, "invalid-response.txt")
	defer ts.Close()

	PwnedPasswordAPI = ts.URL
	count, err := Count("test")
	g.Expect(count).Should(gomega.Equal(0))
	g.Expect(err).Should(gomega.Equal(ErrInvalidResponse))
}
