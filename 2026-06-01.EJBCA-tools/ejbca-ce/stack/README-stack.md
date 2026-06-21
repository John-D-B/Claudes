# Local EJBCA-CE Stack

Companion to [../Docs/ejbca-ce-implementation-plan.md](../Docs/ejbca-ce-implementation-plan.md)<br/>
&nbsp; &nbsp; and [../Docs/ejbca-ce-mariadb.md](../Docs/ejbca-ce-mariadb.md). The compose<br/>
&nbsp; &nbsp; file in this directory brings up a two-container EJBCA Community Edition<br/>
&nbsp; &nbsp; stack — MariaDB plus the `keyfactor/ejbca-ce` image — with persistent<br/>
&nbsp; &nbsp; named volumes for both.

## Quick start

```sh
$ cd stack
$ docker compose up -d
$ docker compose logs -f ejbca         # follow startup until "EJBCA started"
```

First-boot startup takes a few minutes: MariaDB initialises, then EJBCA runs<br/>
&nbsp; &nbsp; schema creation, deploys the EAR, and generates the bootstrap SuperAdmin<br/>
&nbsp; &nbsp; certificate.

Open the admin GUI at https://localhost:8443/ejbca/adminweb/ — the browser<br/>
&nbsp; &nbsp; will reject the connection until you import the SuperAdmin P12 (next<br/>
&nbsp; &nbsp; task in the implementation plan).

## Reset / teardown

`$ docker compose down` stops and removes the containers but keeps the volumes.

`$ docker compose down -v` also removes the named volumes — full clean slate,<br/>
&nbsp; &nbsp; useful between fix-prototype iterations.

## Notes

The passwords in `docker-compose.yml` are intentionally trivial — this is a<br/>
&nbsp; &nbsp; throwaway local dev instance, not a production deployment. Move them to a<br/>
&nbsp; &nbsp; gitignored `.env` and reference via `${MARIADB_PASSWORD}` etc. if this<br/>
&nbsp; &nbsp; stack ever grows beyond local use.

For the MariaDB persistence choice (named volume vs bind mount vs native), see<br/>
&nbsp; &nbsp; [../Docs/ejbca-ce-mariadb.md](../Docs/ejbca-ce-mariadb.md).
