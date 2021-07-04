package apigw

import data.authzs

default allow = false

allow {
	valid_jwt
	reqested_resource_allowed
}

reqested_resource_allowed {
	[_, payload, _] := io.jwt.decode(input.token)
	authz = authzs[_]
	regex.match(authz.resource, input.resource)
	operation_allowed(authz.operations, input.operation)
	allowed_to_match(authz.allowed_to.user_groups, payload.userGroups)
}

reqested_resource_allowed {
	[_, payload, _] := io.jwt.decode(input.token)
	authz = authzs[_]
	regex.match(authz.resource, input.resource)
	operation_allowed(authz.operations, input.operation)
	allowed_to_match(authz.allowed_to.app_clients, payload.appClient)
}

operation_allowed(allowed, value) {
	allowed[_] = "*"
}

operation_allowed(allowed, value) {
	allowed[_] = value
}

allowed_to_match(allowed, value) {
	allowed[_] = value
}

allowed_to_match(allowed, value) {
	allowed[_] = "*"
}

# https://play.openpolicyagent.org/p/9af2cRleIv
valid_jwt {
	jwks = jwks_request("https://authorization-server.example.com/jwks").body
	io.jwt.verify_rs256(input.token, json.marshal(jwks))
}

jwks_request(url) = http.send({
	"url": url,
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 3600, # Cache response for an hour
})
