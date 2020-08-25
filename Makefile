message="changes"

bandit:
	bandit -q -s B112 -r ./dredd-cli dredd/

format:
	black -l 120 dredd-cli dredd/

update:
	git add .
	git commit -a -m "$(message)"
	git push

push-master: bandit format update

push: format update

test:
	python -m unittest discover -v

build-suricata:
	cat dockerfiles/suricata.dockerfile | docker build -t 2xxesra/suricata -
