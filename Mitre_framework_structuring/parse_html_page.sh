#!/bin/bash
# run like so:
# 
# (echo "MITRE={"; for x in $(ls *.html); do ./parse_html_page.sh $x ; done ; echo "}" )  > d.py
#(echo "MITRE={"; for x in recon.html resource_dev.html inital_access.html execution.html persistence.html escalation.html evasion.html credential_access.html discovery.html lateral.html collection.html command_control.html exfil.html  impact.html; do ./parse_html_page.sh $x ; done ; echo "}" )  > d.py

CAT=$(cat $1 | grep -A2 "h1" | tr "\n" " " |  sed 's/<h1>\(.*\)<\/h1>.*/\1/' | tr -d "[:blank:]");
DES=$(cat $1 | tr "\n" " " | sed 's/<div/\n<div/g' | grep "description-body" | sed 's/<div class="description-body">\(.*\)<\/div>.*/\1/' | sed 's/<\/div>//' | sed 's/<p>//g' | sed 's/<\/p>//g' | sed 's/^[\t ]*//' | sed 's/[ \t]*$//'  );


ROWS=$(cat $1 | tr "\n" " " | sed 's/<tr/\n<tr/g' | grep "^<tr" | sed 's/<\/tr>.*/<\/tr>/' )


IMV=$( echo $ROWS | sed 's/<tr/\n<tr/g' | grep 'tech' | sed 's/<[^>]*>//g' | sed 's/^[ \t]*//' | sed 's/   /\t/g' | sed 's/[\t ]*$//' | awk -F"\t"\
       'BEGIN{LL=0;} 
        $1 ~ /^T/{  gsub(/^[ \t]+/,"",$2); gsub(/[ \t]+$/,"",$2);
                    gsub(/^[ \t]+/,"",$3); gsub(/[ \t]+$/,"",$3); 
		    gsub(/\\/,"/",$3);gsub(/"/,"\\\"",$3); 	     
                    if ( LL == 0 ){ 
		                print ""; } 
		    else { 
		                if ( LL == 1 ) { 
				           print " }}, "; } 
                                else { print "}}, ";  };  
                     } ; 
                     print "\"" $2 "\":{\"tag\":\"" $1 "\", \"description\":\"" $3 "\", \"subtypes\":{" ; 
		     LL = 1; 
                 }; 
        $1 ~ /^\./{ gsub(/^[ \t]+/,"",$2);gsub(/[ \t]+$/,"",$2);
                    gsub(/^[ \t]+/,"",$3);gsub(/[ \t]+$/,"",$3); 
		    gsub(/\\/,"/",$3);gsub(/"/,"\\\"",$3); 	     
		    if ( LL == 2 ){
		       print "," ; }
		    else  {
		       print ""; 
                    };
		    print "\"" $2 "\":{\"tag\":\"" $1 "\", \"description\":\"" $3 "\"}" ; 
		    LL = 2 
                  }; 
        END{ if (LL == 1){ print "}}," } else {print "}}," } }' );


echo -e "\t\"$CAT\":{"
echo -en "\t\t" 
echo -n $IMV  | sed 's/}},/}},\n/g'  | sed 's/\"T/\t\t\"T/g' | sed 's/\"\.0/\n\t\t\t\"\.0/g'

echo -e "\t\t\"category-description\":\"$DES\"}," 


