.PHONY: package deploy

PROFILE:=default
REGION:=us-east-2
UPLOAD_BUCKET:=anjou-sl-resources
STACK_NAME:=discobot

package: deployment.yaml
build: .aws-sam/build/template.yaml

.aws-sam/build/template.yaml: template.yaml $(shell find src -name '*.py' -or -name 'requirements.txt')
	pipenv run sam build --region "${REGION}"

deployment.yaml: .aws-sam/build/template.yaml
	pipenv run sam package --profile "${PROFILE}" --region "${REGION}" \
		--s3-bucket "${UPLOAD_BUCKET}" --output-template-file "$@"

deploy: deployment.yaml
	pipenv run sam deploy --profile ${PROFILE} --region ${REGION} --template-file "$<" \
		--stack-name ${STACK_NAME} --capabilities CAPABILITY_NAMED_IAM

