# W. Casey
import os, sys, re, glob, copy
import json


rules = {
        "<Esc>":None,
        "<BckSp>":None,
        "<Tab>":None,  
        "<Enter>":None, 
        "<LCtrl>":None,"<RCtrl>":None,
        "<LShft>":None,"<RShft>":None,
        "<CpsLk>":None,
        "<LAlt>":None,"<CpsLk>":None,
        "<F1>":None,"<F2>":None,"<F3>":None,"<F4>":None,"<F5>":None,"<F6>":None,
        "<F7>":None,"<F8>":None,"<F9>":None,"<F10>":None,"<F11>":None,"<F12>":None,
        "<NumLk>":None,"<ScrLk>":None,
        "<KP+>":None,"<KP1>":None,"<KP2>":None,"<KP3>":None,"<KP0>":None,"<KP.>":None,
        "<KP7>":None,"<KP8>":None,"<KP9>":None,"<KP->":None,"<KP4>":None,"<KP5>":None,"<KP6>":None,
        "<KPEnt>":None,"<KP/>":None,
        "<PrtSc>":None,"<AltGr>":None,"<Break>":None,
        "<Home>":None,"<Up>":None,"<PgUp>":None,"<Left>":None,"<Right>":None,"<End>":None,"<Down>":None,"<PgDn>":None,
        "<Ins>":None,"<Del>":None,"<Pause>":None,"<LMeta>":None,"<RMeta>":None,"<Menu>":None
}


class buffer_input:
        
        shell_rules = copy.deepcopy( rules );
        
        def __init__( self , raw_input ):
                self.raw_input = self.process_raw( raw_input )
                self.buff = []
                self.left = 0;
                self.right = 0;
                self.cur = 0;

        def process_raw( self, raw_input ):
                retval = []; # returns a list of items, item is keystroke Interp or control action
                c = 0;
                while c < len( raw_input ):
                        ctl = False;
                        if ( raw_input[c] == '<' ):
                                for r,f in rules.items():
                                        if ( raw_input.find(r, c ) == c ):
                                                retval.append( r );
                                                ctl = True;
                                                c = c + len( r ); 
                        if ( ctl == False ):
                                retval.append( raw_input[c] ); 
                                c += 1;
                return retval;

        def interprete_bash( self , DEBUG = 0): #0xffffff):
                # de we need this?  here are counts across the data set.
                # 
                # cnt  | rule
                # ------------
                # 3    | RULE 1 
                # 2    | RULE 3 
                # 280  | RULE 5 
                # 153  | RULE 6 
                # 2292 | RULE 7 
                buf = [];
                l = 0 ;
                c = 0 ;
                r = 0 ;
                seq = copy.deepcopy( self.raw_input );
                # https://www.makeuseof.com/linux-bash-terminal-shortcuts/  bash move commands                 
                while ( len( seq )):
                        x = seq[0:]
                        if (len(x) > 1) and ((x[0] == "<LCtrl>") or (x[0] == "<RCtrl>")) and ((x[1] == "a" ) or ( x[1] == "A" )):
                                c = 0 ;     # Ctrl + A           # Move to the start of the command line
                                if ( DEBUG & 1):
                                        print( "RULE 1 " );
                                seq.pop(0); seq.pop(0); continue ;
                        if (len(x) > 1) and ((x[0] == "<LCtrl>") or (x[0] == "<RCtrl>")) and ((x[1] == "e" ) or ( x[1] == "E" )):
                                c = r ;     #Ctrl + E           # Move to the end of the command line
                                if ( DEBUG & 2):
                                        print( "RULE 2 " );
                                seq.pop(0); seq.pop(0); continue ;                                
                        if (len(x) > 1) and ((x[0] == "<LCtrl>") or (x[0] == "<RCtrl>")) and ((x[1] == "f" ) or ( x[1] == "F" )):
                                c = min( c+1, r ); #Ctrl + F           # Move one character forward
                                if ( DEBUG & 4):
                                        print( "RULE 3 " );
                                seq.pop(0); seq.pop(0); continue ;                                
                        if (len(x) > 1) and ((x[0] == "<LCtrl>") or (x[0] == "<RCtrl>")) and ((x[1] == "b" ) or ( x[1] == "B" )):                        
                                c = max( 0, c - 1 ) #Ctrl + B           # Move one character backward
                                if ( DEBUG & 8):
                                        print( "RULE 4 " );                                
                                seq.pop(0); seq.pop(0); continue ;                                
                        if (len(x) > 0) and (x[0] ==  "<Left>" ):                                
                                c = max( 0, c - 1 ) #
                                if ( DEBUG & 16):
                                        print( "RULE 5 " );                                                                
                                seq.pop(0); continue ;                                
                        if (len(x) > 0) and (x[0] ==  "<Right>" ):
                                c = min( c + 1, r ) #
                                if ( DEBUG & 32):
                                        print( "RULE 6 " );                                                                                                
                                seq.pop(0); continue ;                                                                
                        if (len(x) > 0) and (x[0] ==  "<BckSp>" ):
                                c = max( c - 1, 0 ) #
                                r = max( r - 1, 0 ) #
                                if ( DEBUG & 64):
                                        print( "RULE 7 " );                                                                                                                                
                                seq.pop(0); continue ;
                        if (len(x) > 0) and (x[0] in rules ):
                                seq.pop(0); continue ;
                                
                        buf.insert( c, seq.pop( 0 ))
                        c += 1;
                        r += 1; 
                        # these rules are left unimplemented.
                        #Ctrl + XX          # Switch cursor position between start of the command line and the current position
                        #Ctrl + ] + x       # Moves the cursor forward to next occurrence of x
                        #Alt + F / Esc + F  # Moves the cursor one word forward
                        #Alt + B / Esc + B  # Moves the cursor one word backward
                        #Alt + Ctrl + ] + x #  Moves cursor to the previous occurrence of x
                return "".join(buf[:r])

        def get_cmd_name( self, cmd ):
                return cmd[0:cmd.find(" ")]
        
        def count_ctl( self , D = None ):
                if ( D == None ):
                        D = {};
                for k in self.raw_input:
                        if ( len( k ) > 1 ):
                                if k not in D:
                                        D[k] = 0;
                                D[k] += 1;
                return D;
                
        def measure_uncertainty( self , cmd ):
                # This function measures how many keystrokes vs cmd len.
                return (len( cmd ) + 0.0 )/(max(1,len( self.raw_input ) - 1) + 0.0) 

        
### letting L be the input command (so far), a non None function will transform L in place.

def parse_key_seq( stin, D = None ):
        if ( D == None ):
                D = {};
        bil = buffer_input( stin );
        bil.count_ctl( D );
        cmd = bil.interprete_bash();
        ux = bil.measure_uncertainty( cmd );
        cmd_name = bil.get_cmd_name( cmd )
        #print( f" {bil.raw_input} -> {cmd} : {ux} : {cmd_name}"  )
        #print( f" control chars found : {D} " ); 
        return (cmd, cmd_name, ux) ; 	
		 		
		
##########################################################################################################################
def parse_log_file( fin ):
	line_num = 0; capture_num = 0; rv = [];  
	with open( fin ) as f:
		DCTL = {}; 
		for l in f.read().split( "\n" ):
			if '>' in l :
				lp = l.find('>')
				time = l[:lp].strip();
				capture = l[(lp+1):].strip();
				cmd_line, cmd_name, ux = parse_key_seq( capture, D= DCTL ); 
				rv.append( ( time, capture, cmd_line, cmd_name, ux ) );capture_num += 1; 
			line_num += 1;
	return [rv, DCTL, ( line_num, capture_num )];

##########################################################################################################################
def direct_counts( DALL, DCTL ):
	for k in DCTL:	
        	if k not in DALL:
                	DALL[k] = 0;
        	DALL[k] += DCTL[k]; 

def main( data_dir = "data/"):
        with open('enterprise-attack.json') as f:
                MITREFRAME = json.load(f)
        Dataframe = {};
        DC = {};
        for x in glob.glob( data_dir + "*.log" ):
                print( f" .. parsing file {x}" ) ;
                y,DX, (ln,cn)= parse_log_file( x );
                print( f" .. {ln} lines {cn} captures " );
                print( f" .. {DX}" );
                
                direct_counts( DC, DX );
                
                gout = open( x + ".csv" , "w");
                for y1 in y:
                        gout.write( "\t".join([str( y11 ) for y11 in y1 ]) + "\n" ) ;
                gout.close();
                #print( y ) ;
                print( "=" *40 );
                
        print( "last y "*28 );
        print( y )
        for k,v in sorted( DC.items(), key = lambda x : -x[1] ):
                print( f"{k} -> {v}" );
        print( "-"*80 );
        if ( 1 == 0 ):
                for k in MITREFRAME.keys():
                        V = MITREFRAME[k];
                        print( f"{k} -> {len(V)}" )
                MFO = MITREFRAME["objects"]
                print(f"MFO type: {type(MFO)}" );
                for k in MFO[:10]:
                        print( f"{k} " )                
        
        #print ( MITREFRAME.keys() ) ;
main();
