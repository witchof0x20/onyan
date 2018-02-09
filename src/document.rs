// Copyright 2018 witchof0x20
/*  This file is part of onyan.

    onyan is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    onyan is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with onyan.  If not, see <http://www.gnu.org/licenses/>.
*/
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
                // Parse an item
                // Wrap it with an `Option`
                do_parse!(
                    item: item >>
                    (Some(item))
                ) |
                // Parse a newline
                // Return `None` as newlines are not useful data
                do_parse!(
                    newline >>
                    (None)
                )
            )
        ) >>
        // Convert the options into something usable
        (Document::from_parsed_items(items))
    )
);

/// Every Item begins with a KeywordLine, followed by zero or more Objects.
#[derive(Debug)]
pub struct Item {
    /// The main line for the item
    keyword_line: KeywordLine,
    /// Additional objects
    objects: Vec<Object>,
}
impl Item {
    /// Constructor
    // TODO: Add objects to the constructor
    fn new(keyword_line: KeywordLine, objects: Vec<Object>) -> Self {
        Item {
            keyword_line: keyword_line,
            objects: objects,
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
        (Item::new(keyword, objects))
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
#[derive(Debug)]
pub struct Object {
    keyword: Keyword,
    data: Vec<char>,
}
impl Object {
    fn new(keyword: Keyword, data: Vec<char>) -> Self {
        Object { keyword, data }
    }
}
/// Object ::= BeginLine Base64-encoded-data EndLine
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    object<Object>,
    do_parse!(
        begin_line: begin_line >>
        data: many1!(
            one_of!("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=\n")
        ) >> 
        end_line: end_line >>
        (Object::new(begin_line, data))
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
