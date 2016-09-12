:-module(saml,
	 [saml_metadata/2]).

% For this to work, you must have a web server running on port 8082, a signed certificate in /tmp/cert.pem with key in /tmp/key.pem and
% upload the output of saml_metadata(trime2, X) to https://www.testshib.org/register.html to install the metadata.
% You also need a VERY new version of SWI-Prolog, and the xml-enc, xmldsig and c14n modules

% See saml-test.pl for a framework to load all this.
% Note that this is currently just a proof of concept!

user:term_expansion(:-saml_acs(ServiceProvider, Path, Options),
		    [saml_acs_path(ServiceProvider, Path),
		     ( :-http_handler(Path, saml:saml_acs_handler(ServiceProvider, Options), []))]).



%%%		    Configuration
:-multifile(saml:certificate_is_trusted/3).
% Ideally,  this would be saml_certificate/3 and PEMData could be formed from Certificate via write_certificate
% but in practise recovering the X509* from the prolog term is impossible
:-multifile(saml:saml_certificate/4).
:-multifile(saml:saml_idp/2).
:-multifile(saml:saml_simple_sign/2).
:-multifile(saml:saml_audience/2).


% End configuration



form_authn_request(ID, Date, ServiceProvider, ExtraElements, XML):-
        SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol',
        SAML = 'urn:oasis:names:tc:SAML:2.0:assertion',
        XML = element(SAMLP:'AuthnRequest', ['ID'=ID,
                                             'Version'='2.0',
                                             'IssueInstant'=Date,
                                             %'Destination'=Destination,
                                             %'ForceAuthn'=false,
                                             %'IsPassive'=false,
                                             %'ProtocolBinding'='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-GET',
                                             'AssertionConsumerServiceURL'='http://selto.sss.co.nz:8081/saml/auth'],
                      [element(SAML:'Issuer', [], [ServiceProvider]),
                       element(SAMLP:'NameIDPolicy', ['AllowCreate'=true,
                                                      'Format'='urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'], [])|ExtraElements]).


http:authenticate(saml(ServiceProvider), Request, [user_id(UserId)]):-
	( http_in_session(_),
          http_session_data(saml('tr.com.eikon.user.name', UserId))->
            true
        ; otherwise->
            memberchk(request_uri(RelayState), Request),
            get_xml_timestamp(Date),
            uuid(UUID),
	    format(atom(ID), 'a~w', [UUID]),
	    saml_idp(ServiceProvider, BaseURL),
            %Destination = BaseURL,

	    XMLOptions = [header(false), layout(false)],

            form_authn_request(ID, Date, ServiceProvider, [], XML),
            %xmld_signed_DOM(XML, SignedXML, [key_file('key.pem'), key_password('')]),
            with_output_to(string(XMLString), xml_write(current_output, XML, XMLOptions)),
            format(user_error, 'XML:~n~s~n',[XMLString]),
%            with_output_to(string(SignedXMLString), xml_write(current_output, SignedXML, XMLOptions)),
%            format(user_error, '~n~nSignedXML:~n~s~n',[SignedXMLString]),


            setup_call_cleanup(new_memory_file(MemFile),
                               (setup_call_cleanup(open_memory_file(MemFile, write, MemWrite, [encoding(octet)]),
                                                    (setup_call_cleanup(zopen(MemWrite, Write, [format(raw_deflate), level(9), close_parent(false)]),
									format(Write, '~s', [XMLString]),
									close(Write))
                                                    ),
						    close(MemWrite)),
                                 memory_file_to_atom(MemFile, SAMLRequestRaw)
                               ),
                               free_memory_file(MemFile)),
            base64(SAMLRequestRaw, SAMLRequest),
            %SAMLRequest = 'fJHdasMwDIVfJfg+P06XpjVJILQMCtsY69jF7lxHXQ2J3Vny0r39TNPBOthAV9L5dDhSdTKY81y0ng7mCd49IEWnoTcopknNvDPCStQojBwABSmxbe/vRJ5k4ugsWWV79pPh/zMSERxpa1i0WddMFrPZQmY3Ki4LlcWcwzxeFiWP853qYF/yXbHgLHoBh4GpWVgRQEQPG4MkDYVWxudxtoyzxXOIMgtVvrKo/fZZWYN+ALcF96FVwDo41SxsaYmc3nmCSaHN229JU02JxNnQNQeio0jTcRwTBOWdJpAIibJDlV4rq8thH0L+zfrR9lp9Rm3f23HlQBLUjJwHFt1aN0j6+2I84eeO7uL9WSq8wSMovdfQsbS5+F5/sPkCAAD//wMA',
	    format(user_error, 'Encoded request: ~w~n', [SAMLRequest]),
	    % Form the URL
	    parse_url(BaseURL, Parts),
	    (  saml_simple_sign(ServiceProvider, SimpleSignGoal)
	    -> saml_certificate(ServiceProvider, _, _, PrivateKey),
               call(SimpleSignGoal, PrivateKey, XMLString, SAMLRequest, RelayState, ExtraParameters)
	    ;  ExtraParameters = []
            ),
            parse_url(IdPURL, [search(['SAMLRequest'=SAMLRequest, 'RelayState'=RelayState|ExtraParameters])|Parts]),
            %parse_url(IdPURL, [search(['SAMLRequest'=SAMLRequest, 'RelayState'=RelayState, 'SigAlg'='http://www.w3.org/2000/09/xmldsig#rsa-sha1', 'Signature'='WnS5/FJ36RYedfq6plW7/alqd4VXimahD/7K3cwNJj0XESNWaZ6iAu4AjNTDv0Cah+uKaL6ciVsaPp9RBYSNAg8svs96y/sbTdHsaHGdJ3Q3ox6x38TmB9UAI66bhhFnp4Yjjqks1j2U2siEzSVleda6QXz8vhKtfgqYBxK2nqUFk9/XP8PqVb1WsmTJzL/kxDhWD9rOpylPo5cLeBanq6IW4lSJue4crF18wdOqBrO70R9l9Nkdq+UwMAoSN/jZQDCEkR6P+F6SJIwqwEUyIP7kULPVWV029+OTFNNV3n0p3soZA8jSiHmqBRqi1Fvm64Qn99MiueRcsR0mPpD/woA=='])|Parts]),
            format(user_error, 'Redirecting user to~n~w~n', [IdPURL]),
            http_redirect(moved_temporary, IdPURL, Request)
	).

saml_simple_sign(PrivateKey, XMLString, RelayState, ['SigAlg'=SigAlg,'Signature'=Signature]):-
	SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        format(string(DataToSign), 'SAMLRequest=~s&RelayState=~w&SigAlg=~w', [XMLString, RelayState, SigAlg]),
        format(user_error, 'Data to sign:~n~s~n', [DataToSign]),
	sha_hash(DataToSign, Digest, [algorithm(sha1)]),
	rsa_sign(PrivateKey, Digest, RawSignature,
		 [ type(sha1),
		   encoding(octet)
		 ]),
        base64(RawSignature, Signature),
        format(user_error, '~nSignature:~n~w~n', [Signature]).

saml_acs_handler(ServiceProvider, Options, Request):-
	format(user_error, 'Got a callback from IdP!~n', []),
	http_read_data(Request, PostedData, []),
	format(user_error, '~w~n', [PostedData]),
        memberchk('SAMLResponse'=Atom, PostedData),
        memberchk('RelayState'=Relay, PostedData),
        base64(RawData, Atom),
        atom_string(RawData, RawString),
        setup_call_cleanup(open_string(RawString, Stream),
			   load_structure(Stream, XML, [dialect(xmlns), keep_prefix(true)]),
                           close(Stream)),
        open('/tmp/response.xml', write, W), format(W, '~s', [RawString]), close(W),
	xml_write(user_error, XML, []),
	process_response(XML, ServiceProvider, Options),
        http_redirect(moved_temporary, Relay, Request).


propagate_ns([], _, []):- !.
propagate_ns([element(Tag, Attributes, Children)|Siblings],
             NS,
             [element(Tag, NewAttributes, NewChildren)|NewSiblings]):-
        !,
        merge_ns(NS, Attributes, NewAttributes, NewNS),
        propagate_ns(Children, NewNS, NewChildren),
        propagate_ns(Siblings, NS, NewSiblings).
propagate_ns([X|Siblings], NS, [X|NewSiblings]):-
        propagate_ns(Siblings, NS, NewSiblings).

merge_ns([xmlns:Prefix=Value|NS], Attributes, NewAttributes, NewNS):-
        (  select(xmlns:Prefix=NewValue, Attributes, A1)
        -> NewNS = [xmlns:Prefix=NewValue|T],
           NewAttributes = [xmlns:Prefix=NewValue|N]
        ;  A1 = Attributes,
           NewNS = [xmlns:Prefix=Value|T],
           NewAttributes = [xmlns:Prefix=Value|N]
        ),
        merge_ns(NS, A1, N, T).

merge_ns([], A, A, NS):-
        findall(xmlns:Prefix=Value, member(xmlns:Prefix=Value, A), NS).

process_response(XML0, ServiceProvider, Options):-
        SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol',
        SAML = 'urn:oasis:names:tc:SAML:2.0:assertion',
        DS = 'http://www.w3.org/2000/09/xmldsig#',
        propagate_ns(XML0, [], XML),
        XML = [element(ns(_, SAMLP):'Response', _, Response)],
        % Response MAY  contain the following elements  : Issuer, Signature, Extensions
        % Response MAY  contain the following attributes: InResponseTo, Destination, Consent
        % Response MUST contain the following elements  : Status
        % Response MUST contain the following attributes: ID, IssueInstant, Version
	( memberchk(element(ns(_, SAMLP):'Status', _StatusAttributes, Status), Response)->
            % Status MUST contain a StatusCode element, and MAY contain a StatusMessage and or StatusDetail element
	    ( memberchk(element(ns(_, SAMLP):'StatusCode', StatusCodeAttributes, _StatusCode), Status)->
                % StatusCode MUST contain a Value attribute
                ( memberchk('Value'=StatusCodeValue, StatusCodeAttributes)->
                    true
                ; throw(illegal_saml_response)
                )
            ; throw(illegal_saml_response)
            )
        ; throw(illegal_saml_response)
	),
	(  memberchk(element(ns(_, SAML):'Issuer', _, [IssuerName]), Response)
	-> true
	;  IssuerName = {null}
	),

        ( member(element(ns(_, DS):'Signature', _, Signature), Response)->
            xmld_verify_signature(Signature, XML, Certificate, []),
            certificate_is_trusted(ServiceProvider, IssuerName, Certificate)
        ; otherwise->
            % Warning: Message is not signed. Assertions may be though
            true
        ),

	( StatusCodeValue == 'urn:oasis:names:tc:SAML:2.0:status:Success'->
            % The user has authenticated in some capacity. We can now open a session for them
            % Note that we cannot say anything ABOUT the user yet. That will come once we process the assertions
            writeln(open_session)
            %http_open_session(_, [])
        ; StatusCodeValue == 'urn:oasis:names:tc:SAML:2.0:status:Requester'->
            throw(saml_rejected(requester))
        ; StatusCodeValue == 'urn:oasis:names:tc:SAML:2.0:status:Responder'->
            throw(saml_rejected(responder))
        ; StatusCodeValue == 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch'->
            throw(saml_rejected(version_mismatch))
        ; throw(saml_rejected(illegal_response))
        ),

        % Response MAY also contain 0..N of the following elements: Assertion, EncryptedAssertion.
        forall(member(element(ns(SAMLPrefix, SAML):'Assertion', AssertionAttributes, Assertion), Response),
               process_assertion(ServiceProvider, XML, AssertionAttributes, Assertion)),
        forall(member(element(ns(SAMLPrefix, SAML):'EncryptedAssertion', _, EncryptedAssertion), Response),
               ( decrypt_xml(EncryptedAssertion, DecryptedAssertion, saml:saml_key_callback(ServiceProvider), Options),
		 forall(member(element(SAML:'Assertion', AssertionAttributes, Assertion), DecryptedAssertion),
                        process_assertion(ServiceProvider, XML, AssertionAttributes, Assertion))
               )
	      ).


process_assertion(ServiceProvider, Document, Attributes, Assertion):-
        SAML = ns(_, 'urn:oasis:names:tc:SAML:2.0:assertion'),
	DS = ns(_, 'http://www.w3.org/2000/09/xmldsig#'),
        ( memberchk('ID'=_AssertionID, Attributes)->
            true
        ; throw(missing_assertion_id)
        ),
        % An Assertion MUST contain an Issuer, and MAY contain a Signature, Subject, Conditions, Advice, plus 0..N of the following:
        %   Statement
        %   AuthnStatement
        %   AuthzDecisionStatement
        %   AttributeStatement
        % It must also have all the following attributes, Version, ID, IssueInstant
        memberchk(element(SAML:'Issuer', _, [IssuerName]), Assertion),
        debug(saml, 'Received assertion from IdP ~w', [IssuerName]),
        ( member(element(DS:'Signature', _, Signature), Assertion)->
            xmld_verify_signature(Document, Signature, Certificate, []),
            certificate_is_trusted(ServiceProvider, IssuerName, Certificate)
        ; otherwise->
            % Technically the standard allows this, but it seems like practically it would be useless?
            throw(unsigned_response)
        ),
        ( memberchk(element(SAML:'Conditions', ConditionsAttributes, Conditions), Assertion)->
            % If conditions are present, we MUST check them. These can include arbitrary, user-defined conditions
            % and things like ProxyRestriction and OneTimeUse
            get_xml_timestamp(Date),
            ( memberchk('NotOnOrAfter'=Expiry, ConditionsAttributes)->
		Date @< Expiry
            ; true
            ),
            ( memberchk('NotBefore'=Expiry, ConditionsAttributes)->
                Date @> Expiry
            ; true
            ),
            forall(member(element(SAML:'Condition', ConditionAttributes, Condition), Conditions),
                   condition_holds(ConditionAttributes, Condition)),
            forall(member(element(SAML:'AudienceRestriction', _AudienceRestrictionAttributes, AudienceRestriction), Conditions),
		   ( member(element(SAML:'Audience', _, [Audience]), AudienceRestriction),
		     saml_audience(ServiceProvider, Audience)->
                       true
                   ; throw(illegal_audience)
                   )),
            ( memberchk(element(SAML:'OneTimeUse', _, _), Conditions)->
                throw(one_time_use_not_supported)
            ; true
            ),
            ( memberchk(element(SAML:'ProxyRestriction', _, _), Conditions)->
                throw(proxy_restriction_not_supported)
            ; true
            )
        ; true
        ),
        % The Subject element is not mandatory. In the introduction to section 2, the specification states
        % "the <Subject> element is optional, and other specifications and profiles may utilize the SAML assertion
        % structure to make similar statements without specifying a subject, or possibly specifying the subject in an
        % alternate way"
        % However, 2.3.3 goes on to say that
        % "SAML itself defines no such statements, and an assertion without a subject has no defined meaning in this specification."
        % Specifically, 2.7.2, 2.7.3, 2.7.4 enumerate all the SAML-defined statements, and all of them say that the assertion MUST
        % contain a subject
        ( memberchk(element(SAML:'Subject', _, Subject), Assertion)->
            memberchk(element(SAML:'NameID', _, [IdPName]), Subject),
            debug(saml, 'Assertion is for subject ~w', [IdPName]),
            % Note that it is not mandatory for there to be any SubjectConfirmation in the message, however, since we must verify at least one
            % confirmation in order to trust that the subject has really associated with the IdP, a subject with no confirmations is useless anyway
            ( member(element(SAML:'SubjectConfirmation', SubjectConfirmationAttributes, SubjectConfirmation), Subject),
              subject_confirmation_is_valid(SubjectConfirmationAttributes, SubjectConfirmation)->
                debug(saml, 'Subject is confirmed', [])
            ; debug(saml, 'No valid subject confirmation could be found', []),
              throw(no_subject_confirmation)
            )
        ; throw(not_supported(assertion_without_subject))
        ),
        ( memberchk(element(SAML:'AttributeStatement', _, AttributeStatement), Assertion)->
            forall(member(element(SAML:'Attribute', AttributeAttributes, Attribute), AttributeStatement),
                   ( memberchk('Name'=Name, AttributeAttributes),
                     memberchk(element(SAML:'AttributeValue', _, [Value]), Attribute),
                     Key = saml(Name, Value),
                     writeln(assert(Key))
                     %http_session_assert(Key)
                   ))
        ; true
	).

process_assertion(_Attributes, _Assertion, _, _, _, _):-
	debug(saml, 'Warning: Assertion was not valid', []).

condition_holds(_ConditionAttributes, _Condition):-
        throw(conditions_not_implemented).

get_xml_timestamp(Date):-
        get_time(Time),
        stamp_date_time(Time, date(Y, M, D, HH, MM, SSF, _, 'UTC', _), 'UTC'),
        SS is integer(SSF),
        format(atom(Date), '~w-~|~`0t~w~2+-~|~`0t~w~2+T~|~`0t~w~2+:~|~`0t~w~2+:~|~`0t~w~2+Z', [Y,M,D,HH,MM,SS]).


subject_confirmation_is_valid(SubjectConfirmationAttributes, SubjectConfirmation):-
	SAML = ns(_, 'urn:oasis:names:tc:SAML:2.0:assertion'),
        memberchk('Method'='urn:oasis:names:tc:SAML:2.0:cm:bearer', SubjectConfirmationAttributes), % this is the only method we support
        memberchk(element(SAML:'SubjectConfirmationData', Attributes, _SubjectConfirmationData), SubjectConfirmation),
        get_xml_timestamp(Date),
        ( memberchk('NotOnOrAfter'=Expiry, Attributes)->
            Date @< Expiry
        ; true
        ),
        ( memberchk('NotBefore'=Expiry, Attributes)->
            Date @> Expiry
        ; true
        ),
        ( memberchk('InResponseTo'=_InResponseTo, Attributes)->
            % FIXME: Check that we sent the message, somehow?
            true
        ; true
        ),
        ( memberchk('Recipient'=_Recipient, Attributes)->
            % FIXME: Check that this is us, somehow?
            true
        ; true
        ),
        % FIXME: We can also have other arbitrary elements and attributes in here for user-defined extensions. These are ignored.
        true.

saml_key_callback(ServiceProvider, certificate, KeyHint, Key):-
	saml_certificate(ServiceProvider, KeyHint, _, Key), !.



saml_metadata(ServiceProvider, Metadata):-
	MD = 'urn:oasis:names:tc:SAML:2.0:metadata',
	DS = 'http://www.w3.org/2000/09/xmldsig#',

	saml_certificate(ServiceProvider, _X509Certificate, X509Certificate, _PrivateKey),
	% FIXME: All of this should be configurable. Escpecially URLParts.
        EncryptionMethod = 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
        NameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
	ACSBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',

        URLParts = [host(localhost), port(8081), protocol(http)],

	% For the ACS URL out of the metadata
	saml_acs_path(ServiceProvider, Path),
	http_absolute_location(Path, AbsolutePath, []),
	parse_url(ACSLocation, [path(AbsolutePath)|URLParts]),
	string_concat("-----BEGIN CERTIFICATE-----\n", X509CertificateWithoutHeader, X509Certificate),
	string_concat(PresentableCertificate, "-----END CERTIFICATE-----\n", X509CertificateWithoutHeader),
	Metadata = [element(MD:'EntityDescriptor', [entityID=ServiceProvider], [element(MD:'SPSSODescriptor', [protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'], [element(MD:'KeyDescriptor', [use=encryption], [element(DS:'KeyInfo', [], [element(DS:'X509Data', [], [element(DS:'X509Certificate', [], [PresentableCertificate])])]),
																												   element(MD:'EncryptionMethod', ['Algorithm'=EncryptionMethod], [])]),
																						    element(MD:'NameIDFormat', [], [NameIDFormat]),
                                                                                                                                                                                    element(MD:'AssertionConsumerService', [index='0', isDefault=true, 'Binding'=ACSBinding, 'Location'=ACSLocation], [])])])].



qqq1:-
        saml_certificate(_, _, _, PrivateKey),
        DataToSign = "SAMLRequest=hVPbcqIwGH4VJnstJFSpmxE7bqm7Wqx4rNO7LETMLiRsEgTffoOHTutM29s%2F3%2Bk%2FpHdX55m1p1IxwX2AbAgsymORMJ76YLUctrrAUprwhGSCUx8cqAJ3%2FZ4ieVbgUKSi1HP6r6RKW0aJK5woZpg7rQvsOFVV2dWNLWTquBBCB353DKqBfANnvHH7AI4c2G7gBvGKbnx9UEqOBVFMYU5yqrCO8WIwCbFrQ0yUolKbbt5Sis85hRRaxCK7UOoOhF8ytiwzRaK1ZL9LTfHGkF4FFPuwqc0kXMQ7mpMW481kYwqsJ6GnfCoHW02lD1yIvBb0WshbolvcdjHqvABrFPiAJa3SjW7TdeKtBxNSBeWfaJzX%2B4zN6iJCP%2BZE0r%2FhjTtQa2CtL1t1m62OlCrp6Oiory1gF3cai8CskXGij6wmvjL5JUlaCd3bebyzcxHbKi2Uw4LIWSweWZbZRBU1OF0EPppIayhkTvTnE2wqpp3tEWquQDN9AP3zzAqdayUMotZFAdE7b4zayJySeXW2NOk5b4zPKZ4McRR8mQLZ6CrFM%2BOJqFQgcsL4rCQZ2zKaNHKgP4ii4eohRGfDk8flIyyoakY94gmt%2B0YvRWlYzw%2Bbhzy%2B%2FznuJpFYBnIzfb4ftzs8bf8ar7xqNvZeTmJX%2FEvx3e%2Fq%2Fwc%3D&RelayState=x&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1",
        sha_hash(DataToSign, Digest, [algorithm(sha1)]),
	rsa_sign(PrivateKey, Digest, RawSignature,
		 [ type(sha1),
		   encoding(octet)
		 ]),
        base64(RawSignature, Signature),
        format(user_error, '~nSignature:~n~w~n', [Signature]),
        Signature == 'cW4QFALjPMVnTnelV25KWkZaZCxx/MMP3b3MPG3u+gbzZJ102yAoXYDnspSuPMRzIsdRfyoCSv6JprEAoeLuYbc61yVNbrKaS5+ywAV1BR96YAF4R4EWZIk7bdEoSKcHck8t1izawSbb4/FV3s+8P+sjjFwWgk7NuxZFrz4vIIu0XrUKZs5ePZgZNe12DHptAulNEAmO9BdzTj8o1RUK4jhRGyo20/tsXKFnnN0XAGvR5F4FkpIlQUC58YVAc3trT9RvxrtmcXXcOvu0VamrP+Dx+cGgo4tY/S4Z1avJ4JfLRVdyu+0QX+RbPFNWtLUFFqqgW3dBgfZITQCQkWsbew=='.


qqq2:-
         saml_certificate(_, _, _, PrivateKey),
         %DataToSign = "SAMLRequest=fZHdSsNAEIVfJex9fjbWJi5JILQIBRWx4oV3m83ELiS7dWfW1Ld3aStYQW9nzjeHc6Y6GMx5KVpPO%2FME7x6QosM0GhSnTc28M8JK1CiMnAAFKbFt7%2B9EnmRi7yxZZUf2kyn%2BZyQiONLWsGizrpksh2U39Bzi4lrlMeewjEt508XQLQYFRdEVxcCiF3AYmJqFEwFE9LAxSNJQGGV8GWc3cVY%2B81wsSnFVvLKo%2FfZZWYN%2BArcF96FVwHo41CxcaYmc7jzBSaHN229JU50SiaOha3ZEe5Gm8zwnCMo7TSAREmWnKr1UVudiH0L%2BzfrRjlp9Ru042nnlQBLUjJwHFt1aN0n6uzGe8ONE9%2FFwlApvcA9KDxp6ljZn38sPNl8%3D&RelayState=x&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1",
         recode("SAMLRequest=fZHdSsNAEIVfJex9fjbWJi5JILQIBRWx4oV3m83ELiS7dWfW1Ld3aStYQW9nzjeHc6Y6GMx5KVpPO%2fME7x6QosM0GhSnTc28M8JK1CiMnAAFKbFt7%2b9EnmRi7yxZZUf2kyn%2bZyQiONLWsGizrpksh2U39Bzi4lrlMeewjEt508XQLQYFRdEVxcCiF3AYmJqFEwFE9LAxSNJQGGV8GWc3cVY%2b81wsSnFVvLKo%2ffZZWYN%2bArcF96FVwHo41CxcaYmc7jzBSaHN229JU50SiaOha3ZEe5Gm8zwnCMo7TSAREmWnKr1UVudiH0L%2bzfrRjlp9Ru042nnlQBLUjJwHFt1aN0n6uzGe8ONE9%2fFwlApvcA9KDxp6ljZn38sPNl8%3d&RelayState=x&SigAlg=http%3a%2f%2fwww.w3.org%2f2000%2f09%2fxmldsig%23rsa-sha1", DataToSign),
         format(user_error, 'Recoded data to sign:~n~s~n', [DataToSign]),
        sha_hash(DataToSign, Digest, [algorithm(sha1)]),
	rsa_sign(PrivateKey, Digest, RawSignature,
		 [ type(sha1),
		   encoding(octet)
		 ]),
        base64(RawSignature, Signature),
        format(user_error, '~nSignature:~n~w~n', [Signature]).


qqq:-
        saml_certificate(_, _, _, PrivateKey),
        DataToSign="SAMLRequest=fJHdasMwDIVfJfg%2BP06XpjVJILQMCtsY69jF7lxHXQ2J3Vny0r39TNPBOthAV9L5dDhSdTKY81y0ng7mCd49IEWnoTcopknNvDPCStQojBwABSmxbe%2FvRJ5k4ugsWWV79pPh%2FzMSERxpa1i0WddMFrPZQmY3Ki4LlcWcwzxeFiWP853qYF%2FyXbHgLHoBh4GpWVgRQEQPG4MkDYVWxudxtoyzxXOIMgtVvrKo%2FfZZWYN%2BALcF96FVwDo41SxsaYmc3nmCSaHN229JU02JxNnQNQeio0jTcRwTBOWdJpAIibJDlV4rq8thH0L%2BzfrR9lp9Rm3f23HlQBLUjJwHFt1aN0j6%2B2I84eeO7uL9WSq8wSMovdfQsbS5%2BF5%2FsPkCAAD%2F%2FwMA&RelayState=x&SigAlg=http%3a%2f%2fwww.w3.org%2f2000%2f09%2fxmldsig%23rsa-sha1",
        sha_hash(DataToSign, Digest, [algorithm(sha1)]),
	rsa_sign(PrivateKey, Digest, RawSignature,
		 [ type(sha1),
		   encoding(octet)
		 ]),
        base64(RawSignature, Signature),
        format(user_error, '~nSignature:~n~w~n', [Signature]).



recode(In, Out):-
        string_codes(In, I),
        recode_1(I, O),
        string_codes(Out, O).

recode_1([], []):- !.
recode_1([37,A,B|R], [37, AA, BB|S]):- !,
        atom_codes(Atom, [A,B]),
        upcase_atom(Atom, Up),
        atom_codes(Up, [AA,BB]),
        recode_1(R, S).
recode_1([A|As], [A|Bs]):-
        recode_1(As, Bs).


