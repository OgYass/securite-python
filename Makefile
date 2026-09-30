IMAGE ?= pysec
TP ?= tp1

.PHONY: run

run:
	docker build -t $(IMAGE) .
	docker run -it --network host $(IMAGE) -v "$(CURDIR)/out:/app/out" $(IMAGE)