:-use_module(library(http/http_dispatch)).
:-use_module(library(http/http_wrapper)).
:-use_module(library(http/http_session)).
:-use_module(library(http/http_open)).
:-use_module(library(http/http_client)).
:-use_module(library(http/thread_httpd)).
:-use_module(library(http/http_path)).
:-use_module(library(ssl)).

:-use_foreign_library(bin/base64).
:-ensure_loaded('./saml').
:-ensure_loaded('../xml-enc').
:-ensure_loaded('../xmldsig/xmldsig').
:-ensure_loaded('../c14n2/c14n2').


test:-
	http_server(http_dispatch:http_dispatch, [port(8082),
                                                  timeout(60),
                                                  workers(5),
                                                  timeout(5),
                                                  keep_alive_timeout(5)]).