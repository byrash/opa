package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/open-policy-agent/opa/rego"
)

func main() {
	r := rego.New(
		rego.Query("allow_api_call = data.apigw.decision"),
		rego.Load([]string{"opa_apigw.rego", "opa_authz_data.json"}, nil),
		rego.Dump(os.Stdout))
	ctx := context.Background()
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		panic(err)
	}

	// Load the input document from stdin.
	var input interface{}
	dec := json.NewDecoder(os.Stdin)
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		log.Fatal(err)
	}

	// Execute the prepared query.
	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
	}

	b, err := json.Marshal(rs[0].Bindings["allow_api_call"])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}
