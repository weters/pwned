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
