﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OidcApiAuthorization.Models
{
    public class JwksKey
    {
        public string kty { get; set; }
        public string e { get; set; }
        public string use { get; set; }
        public string kid { get; set; }
        public string n { get; set; }
    }
}
