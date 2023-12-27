package main

import (
	groth16 "github.com/Portkey-Wallet/go-groth16"
)

func main() {
	ctx := groth16.LoadContext("./data-files/guardianhash.wasm", "./data-files/guardianhash.r1cs", "./data-files/guardianhash_0001.zkey")
	defer ctx.Free()
	res := ctx.Prove("{\"jwt\": [\"101\", \"121\", \"74\", \"104\", \"98\", \"71\", \"99\", \"105\", \"79\", \"105\", \"74\", \"83\", \"85\", \"122\", \"73\", \"49\", \"78\", \"105\", \"73\", \"115\", \"73\", \"110\", \"82\", \"53\", \"99\", \"67\", \"73\", \"54\", \"73\", \"107\", \"112\", \"88\", \"86\", \"67\", \"74\", \"57\", \"46\", \"101\", \"121\", \"74\", \"122\", \"100\", \"87\", \"73\", \"105\", \"79\", \"105\", \"73\", \"120\", \"77\", \"106\", \"77\", \"48\", \"78\", \"84\", \"89\", \"51\", \"79\", \"68\", \"107\", \"119\", \"73\", \"105\", \"119\", \"105\", \"98\", \"109\", \"70\", \"116\", \"90\", \"83\", \"73\", \"54\", \"73\", \"107\", \"112\", \"118\", \"97\", \"71\", \"52\", \"103\", \"82\", \"71\", \"57\", \"108\", \"73\", \"105\", \"119\", \"105\", \"89\", \"87\", \"82\", \"116\", \"97\", \"87\", \"52\", \"105\", \"79\", \"110\", \"82\", \"121\", \"100\", \"87\", \"85\", \"115\", \"73\", \"109\", \"108\", \"104\", \"100\", \"67\", \"73\", \"54\", \"77\", \"84\", \"85\", \"120\", \"78\", \"106\", \"73\", \"122\", \"79\", \"84\", \"65\", \"121\", \"77\", \"110\", \"48\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\"], \"signature\": [\"136066698678378650066472176144548241\", \"1800384327008418817146654168653894619\", \"2574524618487272827404567912127994032\", \"1572551955913018780280859127440201929\", \"1890564471282023685923539663639306374\", \"1866512077014082189748713566387377304\", \"2222710341065048773940709188556978891\", \"840541024972195344747634213092278743\", \"330476852732802730001627869075985501\", \"1294859790995514400195378924750900104\", \"1136356663482937321790125666232087630\", \"2501709109099362467808413692918409573\", \"1776875315524942066973947221991971257\", \"913872260108236275630951234884908773\", \"1608150223070592825745836511435000141\", \"1583177297555626922284372616305354634\", \"1063982966443379747600844439851650\"], \"pubkey\": [\"5841544268561861499519250994748571\", \"282086110796185156675799806248152448\", \"2181169572700087019903500222780233598\", \"1322589976114836556068768894837633649\", \"1794113848426178665483863008905364300\", \"543380795324313410170505147425740531\", \"1493214249295981343844955353860051664\", \"2171199579242924905862250512208697455\", \"1395394319132308840130123038054629304\", \"1562009664380263536909338779810969578\", \"1594567849407226969396248621216777848\", \"2058356264851095114515728757906168363\", \"836769104848661443299826291369000556\", \"1779001964758400339025173335511101862\", \"2544058187525854999124570613534759403\", \"424565350689075956046563544271353450\", \"3799511822475913352444008446631779\"], \"salt\": [\"97\", \"54\", \"55\", \"55\", \"57\", \"57\", \"57\", \"51\", \"57\", \"54\", \"100\", \"99\", \"52\", \"57\", \"97\", \"50\", \"56\", \"97\", \"100\", \"54\", \"99\", \"57\", \"99\", \"50\", \"52\", \"50\", \"55\", \"49\", \"57\", \"98\", \"98\", \"51\"]}")
	println(res)
}
