let Loader = function () {
    this.element = $("#loading");
};
Loader.prototype = {
    show: function () {
        this.element.show()
    },
    hide: function () {
        this.element.attr("style", "display: none !important;")
    }
};

let hashID = (function () {
    let module = {};
    let hashDefs = {};
    let defsLoaded = false;
    let btnSubmit;
    let loader;
    let results;
    let hashInput;

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
    function loadFromURL() {
        var query = window.location.search;
        var queryParams = parseQuery(query);
        if (queryParams["hashes"]) {
            let input = queryParams["hashes"].split(",").join("\n");
            if(input) {
                hashInput.val(input);
                btnSubmit.click();
            }
        }
    }

    module.init = function () {
        loader = new Loader();
        btnSubmit = $("#submit");
        results = $(".results");
        hashInput = $("#hashes");

        $.ajax({
            dataType: 'json',
            url: './data/hashtypes.json'
        }).done((defs) => {
            hashDefs = defs;
            btnSubmit.attr("disabled", false);
            defsLoaded = true;
            loadFromURL();
        });
    }

    module.submit = function () {
        loader.show();
        if(defsLoaded) {
            function toHtml(hash) {
                const template = `
                <h4>${hash.value}</h4>
                <ul>
                    ${hash.matches.map(match => `<li>${match}</li>`).join('')}
                </ul>
                `;
                return template;
            }

            let hashes = hashInput.val().split("\n");
            let resultList = [];
            hashes.forEach(hash => {
                console.log(hash);
                hash = {
                    value: hash,
                    matches: []
                };
                hashDefs.forEach(def => {
                    let regex = new RegExp(def.regex);
                    if(regex.test(hash.value)) {
                        def.modes.forEach(mode => {
                            hash.matches.push(mode.name);
                        });
                    }
                });
                resultList.push(hash);
            });
            loader.hide();
            resultList.forEach(result => {
                results.append(toHtml(result));
            });
        } else {
            console.log("Definitions not loaded.");
        }
    };
    module.getShareURL = function () {

    };
    return module;
}());
$(document).ready(function () {
    hashID.init();
});