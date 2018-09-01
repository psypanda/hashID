var hashID = (function() {
   var module = {};
   var hashList = {};

   // Source: https://stackoverflow.com/a/13419367/2650847
   function parseQuery(queryString) {
      var query = {};
      var pairs = (queryString[0] === '?' ? queryString.substr(1) : queryString).split('&');
      for (var i = 0; i < pairs.length; i++) {
         var pair = pairs[i].split('=');
         query[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1] || '');
      }
      return query;
   }

   module.submit = function(hashes) {
       hashList = hashes;
   };
   module.loadFromURL = function() {
      var query = window.location.search;
      var queryParams = parseQuery(query);
      if(queryParams["hashes"]) {

      }
   };
   module.getShareURL = function() {

   };
   return module;
}());