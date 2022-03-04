local ngx = ngx
local balancer = balancer

local _M = {}

local function cookie_val(cookie, key)
  return cookie:match(key .. "=([^ ;]+)")
end

-- Check for authentication in headers and cookies and possibly transform
-- cookie authentication information to Bearer Token.
-- Return 'true' if such information exists, else 'false'
local function rewrite_authentication(headers)
  if headers["Authorization"] ~= nil then
    return true
  end

  local cookie = headers["Cookie"]
  if cookie == nil then
    return false
  elseif cookie_val(cookie, "_oauth2_proxy") ~= nil then
    return true
  elseif cookie_val(cookie, "_oauth2_proxy-dev") ~= nil then
    return true
  end
  
  local jwt = cookie_val(cookie, "access_token")
  if jwt ~= nil then
    ngx.req.set_header("Authorization", "Bearer " .. jwt)
    ngx.req.clear_header("Cookie")
    return true
  end
  return false
end

local function teams_rewrite(headers, authenticated)
  -- Teams on development domain
  if headers["Host"] == "dev.teams.xxx.de" then
    if authenticated then
      ngx.req.set_header("Forward-To", "dev.teamsapp.xxx.de")
    else
      ngx.req.set_header("Forward-To", "dev.authhelper.xxx.de")
    end
  -- Teams on production domain
  elseif headers["Host"] == "teams.xxx.de" then
    if authenticated then
      ngx.req.set_header("Forward-To", "teamsapp.xxx.de")
    else
      ngx.req.set_header("Forward-To", "authhelper.xxx.de")
    end
  end
end

-- This function runs on every nginx request in the 'rewrite' stage
function _M.rewrite()
  local headers = ngx.req.get_headers()
  local authenticated = rewrite_authentication(headers)
  teams_rewrite(headers, authenticated)
end

return _M