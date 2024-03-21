pub fn get_token_from_request(request: &str) -> Result<&str, std::io::Error> {
    let token = request
        .split("Authorization: Bearer ")
        .nth(1)
        .unwrap_or_default()
        .split("\r\n")
        .next()
        .unwrap_or_default();
    Ok(token)
}

pub fn get_id_from_request(request: &str) -> &str {
    request
        .split('/')
        .nth(2)
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or_default()
}
