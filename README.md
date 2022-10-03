using libmodsecurity3
using ModSecurity/NGINX connector - https://github.com/SpiderLabs/ModSecurity-nginx.git
I am experiencing an issue with ModSecurity blocking updates to my theme options.
I am using the Avada theme.
I have looked on the The ModSecurity user’s mailing list but could not find it.
nginx/error.log entry:
2022/10/01 09:07:38 [error] 20306#20306: *15372 [client 75.4.208.96] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `45' ) [file "/etc/nginx/modsec/coreruleset-3.3.0/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "80"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 45)"] [data ""] [severity "2"] [ver "OWASP_CRS/3.3.0"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "172.31.63.203"] [uri "/wp-admin/admin-ajax.php"] [unique_id "166462965858.610384"] [ref ""], client: 75.4.208.96, server: rjns.com, request: "POST /wp-admin/admin-ajax.php?_fs_blog_admin=true HTTP/2.0", host: "www.rjns.com", referrer: "https://www.rjns.com/wp-admin/themes.php?page=avada_options"
I have modified coreruleset-3.3.0/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf
# Edit posts and pages
# /wp-admin/post.php, /wp-admin/post.php?t=[timestamp]
# - Themes do not properly escape post_title in HTML, so beware of XSS
#   and be conservative in excluding this parameter.
# - Parameter _wp_http_referer can appear multiple times.
# rjb 20220921 added ctl:ruleRemoveById=949110
SecRule REQUEST_FILENAME "@endsWith /wp-admin/post.php" \
    "id:9002700,\
    phase:2,\
    pass,\
    t:none,\
    nolog,\
    ver:'OWASP_CRS/3.3.0',\
    chain"
    SecRule ARGS:action "@rx ^(?:edit|editpost)$" \
        "t:none,\
        chain"
        SecRule &ARGS:action "@eq 1" \
            "t:none,\
            ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:post_title,\
            ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:content,\
            ctl:ruleRemoveById=920272,\
            ctl:ruleRemoveById=921180,\
            ctl:ruleRemoveById=949110"
This only fixes the Edit posts and pages.
Help would me much apprecieated.
