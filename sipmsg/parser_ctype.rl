// -*-go-*-
//
// Content Type header parser
package sipmsg

%% machine ctype;
%% write data;

func parseContentType (data []byte) (*ContentType, error) {
    cs := 0
    l := ptr(len(data))
    var p, m, pe, eof ptr = 0, 0, l, l
    var prm_name, prm_val pl;
    ct := &ContentType{}

%%{
    action sm        { m = p }
    action media     { ct.mtype = data[m:p] }
    action subtype   { ct.msubtype = data[m:p] }
    action prm_name  { prm_name.p = m; prm_name.l = p }
    action prm_val   { prm_val.p = m; prm_val.l = p }
    action prm_qval  { prm_val.p = m + 1; prm_val.l = p - 1 }
    action prm_set   {
        if ct.params == nil {
            ct.params = make(map[string][]byte)
        }
        ct.params[string(data[prm_name.p:prm_name.l])] = data[prm_val.p:prm_val.l]
    }

    include grammar "grammar.rl";

    param          = token >sm %prm_name EQUAL (token >sm %prm_val | quoted_string >sm %prm_qval)
                     %prm_set;
    discret_type   = "text" | "image" | "audio" | "video" | "application" | token;
    composite_type = "message" | "multipart" | token;
    mtype          = discret_type | composite_type | token;

    main          := mtype >sm %media SLASH token >sm %subtype (SEMI param)*; 
}%%

%% write init;
%% write exec;

    if cs >= ctype_first_final {
        return ct, nil
    }
    return nil, ErrorSIPHeader.msg("Invalid content type header: %s", data[m:p])
}
