from difflib import SequenceMatcher
from telnetlib import SE
from mitmproxy import ctx, command, flow, http

def check_domain(target, host):
    if target == "*":
        return True
    else:
        return target == host

def check_similarity(original, modified):
    s = SequenceMatcher(None, original, modified)
    if s.ratio() > 0.95:
        return True
    else:
        return False

class Sanction:
    def __init__(self):
        ctx.log.info("Initialising")
        self.replacement_dict = {}
        self.flow_dict = {}
        self.active = False
        self.false_positive_list = []
    def load(self, loader):
        loader.add_option(
            name = "domain",
            typespec = str,
            default = "*",
            help = "Target Domain (default: *)"
        )

    @command.command("sanction.set_target")
    def set_target(self, flow: flow.Flow) -> None:
        ctx.options.domain = flow.request.host

    @command.command("sanction.set_cookies_from_request")
    def set_cookies_from_request(self, flow: flow.Flow) -> None:
        try:
            cookies = flow.request.headers["Cookie"]
            self.replacement_dict["Cookie"] = cookies
        except KeyError:
            ctx.log.error("Request does not have cookies")

    @command.command("sanction.set_authorization_from_request")
    def set_authorisation_from_request(self, flow: flow.Flow) -> None:
        try:
            authorization_header = flow.request.headers["Authorization"]
            self.replacement_dict["Authorization"] = authorization_header
        except KeyError:
            ctx.log.error("Request does not have an authorisation header")

    @command.command("sanction.false_positive")
    def false_positive(self, flow: flow.Flow) -> None:
        if flow.request.url not in self.false_positive_list:
            ctx.log.info("Adding %s as false positive" % flow.request.url)
            self.false_positive_list.append(flow.request.url)
    @command.command("sanction.activate")
    def start(self) -> None:
        if not self.replacement_dict:
            ctx.log.error("Please specify cookies / headers to replace")
        else:
            self.active = True

    @command.command("sanction.deactivate")
    def stop(self) -> None:
        self.active = False

    def request(self, flow: http.HTTPFlow) -> None:
        # Avoids infinite loop + replays when addon is inactive
        if flow.is_replay == "request" or not self.active or flow.request.url in self.false_positive_list:
            return
        if check_domain(ctx.options.domain, flow.request.host):
            ctx.log.info("Request matched filter and domain")
            self.flow_dict[flow.id] = {
                "original": flow
            }
            # Create a copy of the request and remove the authorisation + cookie header
            no_auth = flow.copy()
            no_auth.marked = ":unlock:"
            no_auth.comment
            no_auth.request.headers.pop("Authorization", None)
            no_auth.request.headers.pop("Cookie", None)
            
            # Setting the original_request flow id in the metadata
            no_auth.metadata["original_request_id"] = flow.id
            no_auth.metadata["type"] = "no_auth"

            # If the replacement dictionary is not empty then we replay with replaced values
            if bool(self.replacement_dict):
                ctx.log.info("Replacing headers")
                alt_auth = flow.copy()
                alt_auth.marked = ":performing_arts:"
                for replacement in self.replacement_dict:
                    alt_auth.request.headers[replacement] = self.replacement_dict[replacement]
                # Setting the original_request flow id in the metadata
                alt_auth.metadata["original_request_id"] = flow.id
                alt_auth.metadata["type"] = "alt_auth"
                ctx.master.commands.call("replay.client", [alt_auth])
            ctx.master.commands.call("replay.client", [no_auth])
    def response(self, flow: http.HTTPFlow) -> None:
        # Here we don't want non replays
        if flow.is_replay != "request":
            return
        
        # Get original flow from flow_dict
        original_request_id = flow.metadata["original_request_id"]
        original_request = self.flow_dict[original_request_id]["original"]
        
        # Compare similarity of response bodies
        if check_similarity(original_request.response.get_content(), flow.response.get_content()):
            ctx.log.info("Responses are similar")
            flow.marked = ":heavy_exclamation_mark:"
addons = [
    Sanction()
]