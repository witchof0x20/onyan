use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use nom::{anychar, IResult};

/// The highest level object is a Document, which consists of one or more Items.
#[derive(Debug)]
pub struct Document {
    /// Items contained within the document
    items: Vec<Item>,
}
impl Document {
    /// Constructor
    /// # Parameters
    /// * `items` - items in the document
    fn new(items: Vec<Item>) -> Self {
        Document { items }
    }
    /// Build from parsed items
    /// # Parameters
    /// * `items` - `Vec` of `Option<Item>` where None represents a newline to be skipped
    /// This exists because an Item can also be
    /// a newline, but those aren't useful
    fn from_parsed_items(items: Vec<Option<Item>>) -> Self {
        Self::new(items.into_iter().flat_map(|item| item).collect())
    }
}
/// Parses a document
/// Document ::= (Item | NL)+
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    pub parse_document<Document>,
    do_parse!(
        items: many1!(
            alt!(
                do_parse!(
                    item: item >>
                    (Some(item))
                ) |
                do_parse!(
                    newline >>
                    (None)
                )
            )
        ) >>
        // Collect the option items into a vector to skip newlines
        (Document::from_parsed_items(items))
    )
);

/// Every Item begins with a KeywordLine, followed by zero or more Objects.
#[derive(Debug)]
pub struct Item {
    keyword_line: KeywordLine,
    objects: Vec<Keyword>,
}
impl Item {
    /// Constructor
    // TODO: Add objects to the constructor
    fn new(keyword_line: KeywordLine) -> Self {
        Item {
            keyword_line: keyword_line,
            objects: vec![],
        }
    }
}
/// Item ::= KeywordLine Object*
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    item<Item>,
    do_parse!(
        keyword: keyword_line >>
        objects: many0!(object) >>
        (Item::new(keyword))
    )
);

#[derive(Debug)]
pub struct KeywordLine {
    keyword: Keyword,
    arguments: Option<Vec<char>>,
}
impl KeywordLine {
    /// Constructor
    fn new(keyword: Keyword, arguments: Option<Vec<char>>) -> Self {
        KeywordLine { keyword, arguments }
    }
}
/// KeywordLine ::= Keyword NL | Keyword WS ArgumentChar+ NL
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    keyword_line<KeywordLine>,
    alt_complete!(
        do_parse!(
            keyword: keyword >>
            newline >>
            (KeywordLine::new(keyword, None))
        ) |
        do_parse!(
            keyword: keyword >>
            whitespace >>
            arguments: many1!(argument_char) >>
            newline >>
            //TODO: Add arguments back
            (KeywordLine::new(keyword, Some(arguments))) 
        )
    )
);

/// Keyword = KeywordChar+
/// KeywordChar ::= 'A' ... 'Z' | 'a' ... 'z' | '0' ... '9' | '-'
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    keyword<Keyword>,
    do_parse!(
        keyword_chars: many1!(
            one_of!("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")
        ) >> (Keyword::from_chars(keyword_chars))
    )
);
#[derive(Debug)]
pub struct Keyword {
    keyword: String,
}
impl Keyword {
    /// Constructor
    fn from_chars(characters: Vec<char>) -> Self {
        Keyword {
            keyword: characters.into_iter().collect(),
        }
    }
}

/// ArgumentChar ::= any printing ASCII character except NL.
// TODO: generate this in a better way
named!(argument_char<char>, one_of!(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"));

/// Object ::= BeginLine Base64-encoded-data EndLine
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    object<Vec<char>>,
    do_parse!(
        begin_line: begin_line >>
        data: many1!(
            one_of!("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=\n")
        ) >> 
        end_line: end_line >>
        (data)
    )
);
/// BeginLine ::= "-----BEGIN " Keyword "-----" NL
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    begin_line<Keyword>,
    delimited!(
        tag!("-----BEGIN "),
        keyword,
        do_parse!(tag!("-----") >> newline >> ())
    )
);
/// EndLine ::= "-----END " Keyword "-----" NL
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    end_line<Keyword>,
    delimited!(
        tag!("-----END "),
        keyword,
        do_parse!(tag!("-----") >> newline >> ())
    )
);
/// NL = The ascii LF character (hex value 0x0a).
named!(newline<char>, char!('\n'));
/// WS = (SP | TAB)+
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    whitespace<Vec<char>>,
    many1!(one_of!(" \t"))
);

/// Test
#[test]
fn test_parse_document() {
    let mut file = File::open("test/barebones.consensus").expect("file not found");
    let mut file_bytes: Vec<u8> = Vec::new();
    file.read_to_end(&mut file_bytes).unwrap();
    let a = parse_document(&file_bytes);
    println!("{:#?}", a);
}
