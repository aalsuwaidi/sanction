from mitmproxy import ctx, http, exceptions

def parse_list(string):
    return string.split(",")
class Sanction:
    def __init__(self):
        ctx.log.info("Initialising")
    def load(self, loader):
        loader.add_option(
            name="place",
            typespec = str,
            default = 'cookies',
            help = "cookies / headers"
        )
        loader.add_option(
            name="names",
            typespec = str,
            default = '',
            help = "List of cookies / headers that should be replaced"
        )
        loader.add_option(
            name="values",
            typespec = str,
            default = '',
            help = "List of replacement values for the selected cookies / headers"
        )
    def configure(self, updates):
        if "names" in updates or "values" in updates:
            self.names = parse_list(ctx.options.names)
            ctx.log.info("Names %s" % self.names)
            self.values = parse_list(ctx.options.values)
            ctx.log.info("Values %s" % self.values)
            if len(self.names) != len(self.values):
                raise exceptions.OptionsError("Number of Keys and Values must be equal")
        if "place" in updates:
            ctx.log.info("Place: %s" % ctx.options.place)
            if ctx.options.place not in ["cookies", "headers"]:
                raise exceptions.OptionsError("Place should either be cookies / headers")
    def request(self, flow: http.HTTPFlow):
        # Avoid Infinite Loop
        if flow.is_replay == "request":
            return 
        if ctx.options.place == "cookies":
            alt_auth = flow.copy()
            no_auth = flow.copy()
            for cookie,value in zip(self.names, self.values):
                if cookie in flow.request.cookies:
                    del no_auth.request.cookies[cookie]
                    alt_auth.request.cookies[cookie] = value
            ctx.master.commands.call("replay.client", [alt_auth])
            ctx.master.commands.call("replay.client", [no_auth])
        else: 
            alt_auth = flow.copy()
            no_auth = flow.copy()
            for header,value in zip(self.names, self.values):
                if header in flow.request.headers:
                    del no_auth.request.headers[cookie]
                    alt_auth.request.headers[header] = value
            ctx.master.commands.call("replay.client", [alt_auth])
            ctx.master.commands.call("replay.client", [no_auth])
addons = [
    Sanction()
]