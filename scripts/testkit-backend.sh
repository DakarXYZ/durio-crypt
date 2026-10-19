#!/usr/bin/env bash
# CR-15: a live dur.io backend for the testkit, in Docker, from the stoatchat
# checkout next to this repo (workspace layout; STOATCHAT_DIR to override).
#
#   scripts/testkit-backend.sh up      # infra (mongo rs0, redis, rabbitmq + management API, MinIO) + debug
#                                      # builds of delta, bonfire, autumn, pushd, each in its own container
#                                      # on durio-test; plus server 2 for T14 (own mongo, redis, rabbit,
#                                      # delta2, bonfire2; TESTKIT_SECOND=0 skips it)
#   scripts/testkit-backend.sh test    # the scenarios (JUnit XML: out/testkit/junit-testkit.xml)
#   scripts/testkit-backend.sh check   # Mongo/MinIO hold ciphertext only (evidence from the last test run)
#   scripts/testkit-backend.sh load    # the load scenario (STOAT_LOAD_USERS, default 50; out/testkit/load.json)
#   scripts/testkit-backend.sh chaos   # chaos scenarios: the test asks, this script stops/restarts containers
#   scripts/testkit-backend.sh peer    # the scripted E2EE peer of the clients' e2e tests (examples/peer.rs,
#                                      # JSON lines on stdin/stdout; built by `up` when TESTKIT_PUBLIC_PORT is set)
#   scripts/testkit-backend.sh down    # services, MinIO, server 2, proxy (infra: tools/rust-dev/test-env.sh down)
#
# TESTKIT_PUBLIC_PORT=14443: also a TLS proxy (Caddy, internal CA) on 127.0.0.1:<port> for apps on
# the host (WEB-08, D7): https://srv1.localhost:<port> is server 1, srv2.localhost server 2, each
# with /.well-known/stoat, /api, /ws, /autumn; the services then advertise these addresses.
#
# Config only through REVOLT__* env vars: E2EE on, open registration without
# e-mail verification or captcha. Rate limits stay on (the testkit backs off on 429).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
WORKSPACE=$(cd .. && pwd)
STOATCHAT_DIR=${STOATCHAT_DIR:-$WORKSPACE/stoatchat}
TEST_ENV=${TEST_ENV:-$WORKSPACE/tools/rust-dev/test-env.sh}
NET=durio-test
IMAGE=durio-rust-dev:local
MINIO_IMAGE=pgsty/silo:RELEASE.2026-09-16T00-00-00Z
MC_IMAGE=pgsty/mc:RELEASE.2026-09-16T00-00-00Z
S3_USER=minioautumn
S3_PASS=minioautumn
SERVICES="delta bonfire autumn pushd"
SECOND="mongo2 redis2 rabbit2 delta2 bonfire2"
RABBIT_API=http://rabbituser:rabbitpass@durio-test-rabbit:15672
CADDY_IMAGE=caddy:2.10.2-alpine
PUBLIC_PORT=${TESTKIT_PUBLIC_PORT:-}
winpath() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }
running() { [ "$(docker container inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }
# a container that did not come up: its state and the end of its log
died() {
    echo "$1 did not start: $(docker container inspect -f 'status={{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' "durio-test-$1" 2>&1)" >&2
    docker logs --tail 30 "durio-test-$1" >&2 2>&1 || true
    exit 1
}

# $1: "" for server 1, "2" for server 2 (T14: its own mongo, redis, rabbit)
revolt_env() {
    n=${1:-}
    rs=rs0
    [ -z "$n" ] || rs=rs1
    if [ -n "$PUBLIC_PORT" ]; then
        site=https://srv${n:-1}.localhost:$PUBLIC_PORT
        set -- "$site" "$site/api" "wss://srv${n:-1}.localhost:$PUBLIC_PORT/ws" "$site/autumn" "$site/january"
    else
        set -- "http://durio-test-delta$n:14702" "http://durio-test-delta$n:14702" "ws://durio-test-bonfire$n:14703" \
            http://durio-test-autumn:14704 http://durio-test-january:14705
    fi
    cat <<EOF
REVOLT__DATABASE__MONGODB=mongodb://durio-test-mongo$n/?replicaSet=$rs
REVOLT__DATABASE__REDIS=redis://durio-test-redis$n/
REVOLT__RABBIT__HOST=durio-test-rabbit$n
REVOLT__HOSTS__APP=$1
REVOLT__HOSTS__API=$2
REVOLT__HOSTS__EVENTS=$3
REVOLT__HOSTS__AUTUMN=$4
REVOLT__HOSTS__JANUARY=$5
REVOLT__FEATURES__E2EE__ENABLED=true
REVOLT__API__REGISTRATION__INVITE_ONLY=false
REVOLT__API__SMTP__HOST=
REVOLT__API__SECURITY__CAPTCHA__HCAPTCHA_KEY=
REVOLT__FEATURES__LIMITS__NEW_USER__OUTGOING_FRIEND_REQUESTS=100
# q11_full_mailbox_retry fills a mailbox; other scenarios stay far below
REVOLT__FEATURES__E2EE__MAX_PENDING_TO_DEVICE=64
REVOLT__FILES__S3__ENDPOINT=http://durio-test-minio:9000
REVOLT__FILES__S3__PATH_STYLE_BUCKETS=true
REVOLT__FILES__S3__REGION=minio
REVOLT__FILES__S3__ACCESS_KEY_ID=$S3_USER
REVOLT__FILES__S3__SECRET_ACCESS_KEY=$S3_PASS
REVOLT__FILES__S3__DEFAULT_BUCKET=revolt-uploads
# T11: pushd publishes to notifications.outbound.fcm; without FCM credentials
# nothing consumes it, the testkit binds its own queue (RabbitMQ management API)
REVOLT__PUSHD__PRODUCTION=false
RUST_LOG=warn
EOF
}

# $1: "" or "2"; the rest: services. No --rm: chaos stops and starts them.
start_services() {
    n=$1
    shift
    mkdir -p out && env_file=out/testkit-backend$n.env  # docker.exe cannot read Git Bash /tmp
    revolt_env "$n" > "$env_file"
    for s in "$@"; do
        docker rm -f durio-test-$s$n >/dev/null 2>&1 || true
        MSYS_NO_PATHCONV=1 docker run -d --name durio-test-$s$n --network $NET --memory 1g --env-file "$env_file" \
            -v durio-cargo-target:/target:ro -w / $IMAGE /target/debug/revolt-$s >/dev/null
    done
    rm -f "$env_file"
}

wait_delta() {
    i=0
    until docker run --rm --network $NET alpine:3.22 wget -qO- "http://$1:14702/" 2>/dev/null | grep -q '"e2ee"'; do
        i=$((i + 1)); [ $i -lt 120 ] || { docker logs "$1" 2>&1 | tail -20 >&2; exit 1; }
        sleep 1
    done
}

up() {
    docker container inspect durio-test-mongo >/dev/null 2>&1 || sh "$TEST_ENV" up
    echo "building revolt-delta, revolt-bonfire, revolt-autumn, revolt-pushd (debug)"
    MSYS_NO_PATHCONV=1 docker run --rm -v "$(winpath "$STOATCHAT_DIR"):/src" \
        -v durio-cargo-target:/target -v durio-cargo-registry:/usr/local/cargo/registry \
        -w /src -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
        $IMAGE cargo build -q -p revolt-delta -p revolt-bonfire -p revolt-autumn -p revolt-pushd

    if ! docker container inspect durio-test-minio >/dev/null 2>&1; then
        docker run -d --rm --name durio-test-minio --network $NET --memory 512m \
            -e MINIO_ROOT_USER=$S3_USER -e MINIO_ROOT_PASSWORD=$S3_PASS $MINIO_IMAGE server /data >/dev/null
    fi
    i=0
    until MSYS_NO_PATHCONV=1 docker run --rm --network $NET -e MC_HOST_m=http://$S3_USER:$S3_PASS@durio-test-minio:9000 \
        $MC_IMAGE mb --ignore-existing m/revolt-uploads >/dev/null 2>&1; do
        i=$((i + 1)); [ $i -lt 30 ] || { echo "minio did not start" >&2; exit 1; }
        sleep 1
    done
    # T11: the test consumer reads the outbound push routing key over HTTP
    docker exec -u rabbitmq durio-test-rabbit rabbitmq-plugins enable --quiet rabbitmq_management >/dev/null

    start_services "" $SERVICES
    wait_delta durio-test-delta
    [ "${TESTKIT_SECOND:-1}" = 0 ] || up_second
    for s in bonfire autumn pushd; do
        running durio-test-$s || { docker logs durio-test-$s 2>&1 | tail -20 >&2; echo "$s exited" >&2; exit 1; }
    done
    [ -z "$PUBLIC_PORT" ] || up_public
    echo "backend up: http://durio-test-delta:14702 ws://durio-test-bonfire:14703 http://durio-test-autumn:14704 (network $NET)"
}

# T14: a second backend with its own database, cache and broker
up_second() {
    if ! running durio-test-mongo2; then
        docker rm -f durio-test-mongo2 durio-test-redis2 durio-test-rabbit2 >/dev/null 2>&1 || true
        docker run -d --name durio-test-mongo2 --network $NET --memory 768m mongo:8 \
            --replSet rs1 --bind_ip_all --wiredTigerCacheSizeGB 0.25 >/dev/null
        docker run -d --name durio-test-redis2 --network $NET --memory 128m redis:7-alpine >/dev/null
        docker run -d --name durio-test-rabbit2 --network $NET --memory 512m \
            -e RABBITMQ_DEFAULT_USER=rabbituser -e RABBITMQ_DEFAULT_PASS=rabbitpass rabbitmq:4-alpine >/dev/null
        i=0
        until docker exec durio-test-mongo2 mongosh --quiet --eval \
            'try { rs.status().ok } catch (e) { rs.initiate({_id: "rs1", members: [{_id: 0, host: "durio-test-mongo2:27017"}]}).ok }' \
            2>/dev/null | grep -q 1; do
            running durio-test-mongo2 || died mongo2
            i=$((i + 1)); [ $i -lt 60 ] || died mongo2
            sleep 1
        done
        i=0
        # the CLI as the rabbitmq user: run as root before the server is up, it creates
        # ~/.erlang.cookie owned by root and the server dies on eacces
        until docker exec -u rabbitmq durio-test-rabbit2 rabbitmq-diagnostics -q check_running >/dev/null 2>&1; do
            running durio-test-rabbit2 || died rabbit2
            i=$((i + 1)); [ $i -lt 60 ] || died rabbit2
            sleep 1
        done
        docker exec -u rabbitmq durio-test-rabbit2 rabbitmqctl eval 'rabbit_exchange:declare(rabbit_misc:r(<<"/">>, exchange,
            <<"revolt.default">>), topic, true, false, false, [], <<"rabbituser">>).' >/dev/null
    fi
    start_services 2 delta bonfire
    wait_delta durio-test-delta2
    echo "server 2 up: http://durio-test-delta2:14702 ws://durio-test-bonfire2:14703"
}

# Apps on the host reach the stack through Caddy with TLS from its internal CA
# (the desktop build allows only https:/wss:); one site per server, like self-hosted
up_public() {
    mkdir -p out
    {
        printf '{\n\tlocal_certs\n\tskip_install_trust\n\tadmin off\n}\n'
        for n in "" 2; do
            [ -z "$n" ] || running durio-test-delta2 || continue
            host=srv${n:-1}.localhost
            printf '%s {\n' "$host"
            printf '\thandle /.well-known/stoat {\n\t\theader Access-Control-Allow-Origin *\n'
            printf '\t\theader Content-Type application/json\n'
            printf '\t\trespond `{"api":"https://%s:%s/api"}`\n\t}\n' "$host" "$PUBLIC_PORT"
            printf '\thandle_path /api* {\n\t\treverse_proxy durio-test-delta%s:14702\n\t}\n' "$n"
            printf '\thandle_path /ws {\n\t\treverse_proxy durio-test-bonfire%s:14703\n\t}\n' "$n"
            printf '\thandle_path /autumn* {\n\t\treverse_proxy durio-test-autumn:14704\n\t}\n}\n'
        done
    } > out/Caddyfile
    docker rm -f durio-test-proxy >/dev/null 2>&1 || true
    MSYS_NO_PATHCONV=1 docker run -d --name durio-test-proxy --network $NET --memory 128m \
        -p "127.0.0.1:$PUBLIC_PORT:443" -v "$(winpath out)/Caddyfile:/etc/caddy/Caddyfile:ro" $CADDY_IMAGE >/dev/null
    echo "building the peer (examples/peer.rs)"
    scripts/dcargo.sh cargo build -q --locked -p stoat-crypto-testkit --example peer
    echo "public: https://srv1.localhost:$PUBLIC_PORT (server 2: srv2.localhost), TLS from Caddy's internal CA"
}

stack_env() {
    e="--network $NET -e STOAT_API=http://durio-test-delta:14702 -e STOAT_WS=ws://durio-test-bonfire:14703"
    e="$e -e STOAT_AUTUMN=http://durio-test-autumn:14704 -e STOAT_TESTKIT_OUT=/work/out/testkit -e STOAT_RABBIT_API=$RABBIT_API"
    if running durio-test-delta2; then
        e="$e -e STOAT_API2=http://durio-test-delta2:14702 -e STOAT_WS2=ws://durio-test-bonfire2:14703"
    fi
    echo "$e"
}

# $1: nextest filter expression, $2: profile
nextest_cmd() {
    cat <<EOF
command -v cargo-nextest >/dev/null || curl -LsSf https://get.nexte.st/0.9/linux | tar zxf - -C /tools/bin
cargo nextest run --locked -p stoat-crypto-testkit --profile $2 --run-ignored only -E '$1'; rc=\$?
cp target/nextest/$2/junit.xml out/testkit/junit-$2.xml 2>/dev/null
exit \$rc
EOF
}

run_test() {
    mkdir -p out/testkit
    DCARGO_DOCKER_ARGS="$(stack_env)" scripts/dcargo.sh sh -c "$(nextest_cmd 'not test(/^(load|chaos)_/)' testkit)"
}

run_load() {
    mkdir -p out/testkit
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    rc=0
    DCARGO_DOCKER_ARGS="$(stack_env) -e STOAT_LOAD=1 -e STOAT_LOAD_USERS=${STOAT_LOAD_USERS:-50}" \
        scripts/dcargo.sh sh -c "$(nextest_cmd 'test(/^load_/)' testkit-serial)" || rc=$?
    server_errors "$since" load
    return $rc
}

# ERROR/panic lines of the services since $1 → out/testkit/<$2>-server-errors.log
server_errors() {
    log=out/testkit/$2-server-errors.log
    for s in $SERVICES; do
        docker logs --since "$1" durio-test-$s 2>&1 | grep -E ' ERROR |panicked' | sed "s/^/$s: /" || true
    done > "$log"
    for s in $SERVICES; do
        printf '%s: %s ERROR/panic lines (%s)\n' "$s" "$(grep -c "^$s: " "$log" || true)" "$log"
    done
}

# The test writes out/testkit/chaos/<n>.req ("restart redis", "stop delta",
# "start delta"); this loop runs it and renames it to <n>.done. Targets:
# redis, rabbit (infra), delta, bonfire, autumn, pushd (services).
run_chaos() {
    dir=out/testkit/chaos
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    rm -rf "$dir" && mkdir -p "$dir"
    name=durio-testkit-chaos
    docker rm -f $name >/dev/null 2>&1 || true
    DCARGO_DOCKER_ARGS="-d --name $name $(stack_env) -e STOAT_CHAOS_DIR=/work/$dir" \
        scripts/dcargo.sh sh -c "$(nextest_cmd "${CHAOS_FILTER:-test(/^chaos_/)}" testkit-serial)" >/dev/null
    docker wait $name > "$dir/exit-code" 2>/dev/null &  # --rm: the container is gone after it exits
    waiter=$!
    docker logs -f $name &
    logs=$!
    while running $name; do
        for req in "$dir"/*.req; do
            [ -e "$req" ] || continue
            read -r action target < "$req" || true
            echo "chaos: $action $target" >&2
            docker "$action" durio-test-"$target" >/dev/null 2>&1 || echo "chaos: $action $target failed" >&2
            if [ "$action" != stop ]; then
                case $target in
                delta) wait_delta durio-test-delta ;;
                rabbit) until docker exec -u rabbitmq durio-test-rabbit rabbitmq-diagnostics -q check_running >/dev/null 2>&1; do sleep 1; done ;;
                esac
            fi
            mv "$req" "${req%.req}.done"
        done
        sleep 0.3
    done
    wait $waiter 2>/dev/null || true
    rc=$(cat "$dir/exit-code" 2>/dev/null || true)
    rc=${rc:-1}
    wait $logs 2>/dev/null || true
    docker rm -f $name >/dev/null 2>&1 || true
    # leave the stack as the scenarios found it (fresh services, nothing
    # left over from the outages)
    for s in redis rabbit; do running durio-test-$s || docker start durio-test-$s >/dev/null; done
    for s in $SERVICES; do docker restart durio-test-$s >/dev/null 2>&1 || docker start durio-test-$s >/dev/null; done
    wait_delta durio-test-delta
    server_errors "$since" chaos
    return "$rc"
}

check() {
    dir=out/testkit/evidence
    ls "$dir"/*.json >/dev/null 2>&1 || { echo "no $dir/*.json: run the tests first" >&2; exit 1; }
    merged=out/testkit/evidence-all.json
    { printf '['; sep=; for f in "$dir"/*.json; do printf '%s' "$sep"; cat "$f"; sep=,; done; printf ']'; } > "$merged"
    docker cp "$merged" durio-test-mongo:/tmp/evidence.json
    rm -f "$merged"
    out=$(docker exec durio-test-mongo mongosh --quiet revolt --eval '
        const runs = JSON.parse(require("fs").readFileSync("/tmp/evidence.json", "utf8"));
        let bad = 0, channels = 0, files = 0;
        for (const ev of runs) {
            for (const m of ev.messages) {
                channels++;
                const docs = db.messages.find({ channel: m.channel, encrypted: { $exists: true } }).toArray();
                if (docs.length === 0) { print("BAD no encrypted messages in " + m.channel); bad++; }
                for (const d of docs) {
                    if (d.content) { print("BAD content stored for " + d._id); bad++; }
                    if (JSON.stringify(d).includes(m.marker)) { print("BAD plaintext in " + d._id); bad++; }
                }
            }
            for (const f of ev.files) {
                files++;
                print("PLAIN " + f.plaintext_sha256);
                const a = db.attachments.findOne({ _id: f.id });
                if (!a || a.encrypted !== true) { print("BAD file " + f.id + " not stored as encrypted"); bad++; continue; }
                if (a.hash === f.plaintext_sha256) { print("BAD file " + f.id + " is the plaintext"); bad++; }
            }
        }
        print(`mongo: ${channels} channels, ${files} files, ${bad === 0 ? "ciphertext only" : bad + " problems"}`);')
    echo "$out" | grep -v '^PLAIN '
    fail=0
    echo "$out" | grep -q '^BAD' && fail=1
    # autumn names objects by the SHA-256 of the upload: none may carry a plaintext hash
    for h in $(echo "$out" | sed -n 's/^PLAIN //p'); do
        if MSYS_NO_PATHCONV=1 docker run --rm --network $NET -e MC_HOST_m=http://$S3_USER:$S3_PASS@durio-test-minio:9000 \
            $MC_IMAGE stat "m/revolt-uploads/$h" >/dev/null 2>&1; then
            echo "BAD MinIO holds an object named by a plaintext hash: $h"
            fail=1
        fi
    done
    [ $fail = 0 ] && echo "minio: no plaintext objects"
    return $fail
}

# The scripted peer (examples/peer.rs) on stdin/stdout
run_peer() {
    DOCKER_TTY=-i DCARGO_DOCKER_ARGS="$(stack_env)" scripts/dcargo.sh target/debug/examples/peer
}

down() {
    for s in $SERVICES minio proxy $SECOND; do docker rm -f durio-test-$s >/dev/null 2>&1 || true; done
    echo "testkit backend down (infra: $TEST_ENV down)"
}

case ${1:-} in
up) up ;;
test) run_test ;;
load) run_load ;;
chaos) run_chaos ;;
check) check ;;
peer) run_peer ;;
down) down ;;
*) sed -n '2,22p' "$0"; exit 2 ;;
esac
