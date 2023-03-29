import pickle
import copy

HEAD = """

use std::collections::HashMap;

macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = ::std::collections::HashMap::new();
         $( map.insert($key, $val); )*
         map
    }}
}

#[derive(Debug)]
pub struct Hnode<'a> {
    d : &'a str ,
    t : &'a str ,
    o : Vec< &'a str>, 
    s : Option< HashMap<&'a str, Hnode<'a> >>
}


impl<'a> Hnode<'a> {
    pub fn get_listing( &self ) -> &Vec<&'a str> {
        & self.o
    }
    pub fn get_sub(&self) -> Option< Vec< &'a str>> {
        match &self.s {
            Some( v ) => Some( v.keys().cloned().collect()),
            None => None
        }
    }
    pub fn get_des(&self, cat: &'a str) -> &'a str{
        match &self.s {
            Some( v ) => match &v.get( cat ) {
                Some( x ) => { x.d },
                None => " -- not found  -- "
            },
            None => "- NA -"
        }
    }
    pub fn get_child(&self, cat : &'a str )-> Option<&Hnode<'a>> {
        match &self.s {
            Some( v ) => match &v.get( cat ) {
                Some( x ) =>  Some( x ),
                None => None
            },
            None => None
        }
        
    }
}


pub fn mitre12() -> Hnode<'static> {
"""

TAIL = """
}

fn main() -> (){
    let MITRE12 = mitre12();
    println!( "{:?}", MITRE12 ); 
}

"""
def safe_str( s ):
    return s.replace( "\"", "QUOTE" ) ; 
def encode_node( D ):
    if "tag" in D and "des" in D: 
        if "subtypes" in D:
            DS = D["subtypes"]
            retval = "\t\t Hnode{ ";
            retval += f"\n\t\t\td:\"{safe_str(D['des'])}\",";
            retval += f"\n\t\t\tt:\"{D['tag']}\","; 
            retval += f"\n\t\t\to:vec![" + ",".join( [f"\"{s}\"" for s in DS ] )   +"],"; 
            if ( len(DS )):
                retval += "\n\t\t\ts: Some("
                retval += "\n\t\t\t\thashmap!("
                retval += "\n\t\t\t\t\t" +  ",\n\t\t\t\t\t".join([ f"\"{s}\" => {encode_node(DS[s])} " for s in DS ] )
                retval += "\n\t\t\t\t)";
                retval += "\n\t\t\t)}"
            else: 
                retval += "\n\t\t\ts: None }" 
            return retval; 
        else:
            return f'''Hnode{{ d:"{safe_str(D['des'])}", t:"{D['tag']}", o:vec![], s: None }} ''' 
    if "category-description" in D:
        DS = copy.copy(D );
        des = DS.pop( "category-description" ); 
        retval = "\tHnode{ ";
        retval += f"\n\t\td:\"safe_str({des})\",";
        retval += f"\n\t\tt:\"None\",";
        retval += f"\n\t\to:vec![" + ",".join( [ f"\"{s}\"" for s in DS] ) + "]," ; 
        if ( len( DS ) ):
            retval += "\n\t\ts: Some("
            retval += "\n\t\t\thashmap!("
            retval += "\n\t\t\t\t" +  ",\n\t\t\t\t".join([ f"\"{s}\" => {encode_node(DS[s])} " for s in DS ] )
            retval += "\n\t\t\t)";
            retval += "\n\t\t)}"
        else: 
            retval += "\n\t\ts: None }"
        return retval;
    else:
        retval = " Hnode{"
        retval += "\n\td:\"_\",";
        retval += "\n\tt:\"None\",";
        retval += "\n\to:vec![" + ",".join( [ f"\"{s}\"" for s in D ] ) + "],";
        retval += "\n\ts:Some(hashmap!( ";
        retval += "\n\t" + ",\n\t".join( [ f"\"{s}\" => {encode_node(D[s])} " for s in D ] );
        retval += "\n\t))}" 
        return retval; 

def main(path = "MITRE12org.pkl" ):
    print( HEAD ); 

    print(f"// processing {path}" );
    U = pickle.load( open( path, "rb" )); 
    rv = encode_node( U ); 
    print( rv );
    print( TAIL ); 
main() ;
