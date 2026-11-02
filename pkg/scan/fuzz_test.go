package scan

import "testing"

// The reference finder and the chunk-loader evaluator read hostile bundles:
// no input may make them panic or loop.
func FuzzChunkLoaders(f *testing.F) {
	for _, s := range []string{
		`r.u=e=>"static/js/"+e+"."+{12:"a1",34:"b2"}[e]+".chunk.js";r.p="/"`,
		`o.u=e=>(76===e?"common":e)+"."+{76:"c3"}[e]+".js"`,
		"r.u=e=>`static/js/${e}.${{12:\"a1\"}[e]}.js`",
		`d.u=function(e){return 2272===e?"x.js":"c/"+(({1:"n"})[e]||e)+"."+({1:"h"})[e]+".js"}`,
		`const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/a.js"])))=>i.map(i=>d[i]);`,
		`self.__next_f.push([1,"3:I[1,[\"static/chunks/a.js\"]]"])`,
		`System.register("a",["./b.js"],function(){});require("./bundle-manifest").register(JSON.parse('["a","b.js"]'))`,
		`function f(s){return/'/.test(s)}import("./x.js")`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, code string) {
		nc := nonCode(code)
		findRefsIn(code, nc)
		ls := chunkLoaders(code, nc)
		for _, l := range ls.loaders {
			publicPath(code, l.rt)
		}
	})
}
