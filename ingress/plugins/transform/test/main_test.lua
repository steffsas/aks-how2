
local main = require("plugins.transform.main")

-- The unit tests are run within a timer phase in a headless Nginx process.
-- Since `set_header` and `ngx.var.http_` API are disabled in this phase we have to stub it 
-- to avoid `API disabled in the current context` error.

describe("main", function()
  describe("rewrite", function()
    it("Transform value of HttpOnly Cookie 'access_token' to Bearer Token.", function()
      ngx.var = { http_cookie = "foo=bar;access_token=test-token-value;hello=world;" }
      stub(ngx.req, "set_header")
      main.rewrite()
      assert.stub(ngx.req.set_header).was_called_with("Authorization", "Bearer test-token-value")
    end)
    
    it("Set forward headers for teams authentication flow (not authenticated).", function()
      ngx.var = { http_host = "dev.teams.xxx.de" }
      stub(ngx.req, "set_header")
      main.rewrite()
      assert.stub(ngx.req.set_header).was_called_with("Forward-To", "dev.authhelper.xxx.de")
    end)
    
    it("Set forward headers for teams authentication flow (authenticated via access_token Cookie).", function()
      ngx.var = { http_host = "dev.teams.xxx.de", http_cookie = "access_token=test-token-value;" }
      stub(ngx.req, "set_header")
      main.rewrite()
      assert.stub(ngx.req.set_header).was_called_with("Forward-To", "dev.teamsapp.xxx.de")
    end)
    
    it("Set forward headers for teams authentication flow (authenticated via oauth2 Cookie).", function()
      ngx.var = { http_host = "dev.teams.xxx.de", http_cookie = "oauth2-proxy=example" }
      stub(ngx.req, "set_header")
      main.rewrite()
      assert.stub(ngx.req.set_header).was_called_with("Forward-To", "dev.teamsapp.xxx.de")

      ngx.var = { http_host = "dev.teams.xxx.de", http_cookie = "oauth2-proxy-dev=example" }
      stub(ngx.req, "set_header")
      main.rewrite()
      assert.stub(ngx.req.set_header).was_called_with("Forward-To", "dev.teamsapp.xxx.de")
    end)
    
    it("Set forward headers for teams authentication flow (authenticated via Bearer Token).", function()
      ngx.var = { http_host = "dev.teams.xxx.de", http_authorization = "Bearer test-token-value" }
      stub(ngx.req, "set_header")
      main.rewrite()
      assert.stub(ngx.req.set_header).was_called_with("Forward-To", "dev.teamsapp.xxx.de")
    end)
  end)
end)
