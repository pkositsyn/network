from aiohttp import web
import argparse
import cache
import handler


def run_server():
    app = web.Application()

    app["cache"] = cache.Cache(capacity=args.cached_records)
    app.router.add_get("/get-a-records", handler.handler)

    web.run_app(app, host="127.0.0.1", port=8080)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cached-records", type=int, default=10)

    args = parser.parse_args()
    run_server()
