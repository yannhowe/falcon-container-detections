.PHONY: build run deploy-k8s run-k8s verify clean

IMAGE := falcon-detections

build:
	docker build -t $(IMAGE) docker/

run:
	docker run --rm --privileged $(IMAGE) /opt/scripts/run-all.sh

run-single:
	@echo "Usage: make run-single SCRIPT=01-container-escape.sh"
	docker run --rm --privileged $(IMAGE) /opt/scripts/$(SCRIPT)

deploy-k8s:
	kubectl apply -f manifests/namespace.yaml
	kubectl apply -f manifests/

run-k8s:
	kubectl create job --from=cronjob/falcon-detections manual-run-$$(date +%s) -n falcon-detections

verify:
	python verify/check.py

verify-verbose:
	python verify/check.py --verbose --hours 8

clean:
	kubectl delete -f manifests/ --ignore-not-found
	docker rmi $(IMAGE) 2>/dev/null || true
