package templates

const SchedulerPolicyConfigTemplate = `
{
	"kind": "Policy",
	"apiVersion": "v1",
	"extenders": [
		{
			"urlPrefix": "{{ .SchedulerUrl }}",
			"apiVersion": "v1beta1",
			"filterVerb": "predicates",
			"bindVerb": "",
			"prioritizeVerb": "",
			"weight": 1,
			"enableHttps": false,
			"nodeCacheCapable": false,
			"httpTimeout": 10000000000
		}
	]
}
`
