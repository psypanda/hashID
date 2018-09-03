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
let CheckBox = function(id) {
    this.element = $(id+" *");
};
CheckBox.prototype = {
    setSelected: function(select) {
        this.element.prop("checked",select);
    },
    isSelected: function() {
        return this.element.is(":checked");
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
    let btnShare;
    let tempid = 0;
    let listed = [];
    let extended;
    let expanded;

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
        var regex = new RegExp('t(rue)?', 'i');
        if(regex.test(queryParams["extended"])) {
            extended.setSelected(true);
        }
        if(regex.test(queryParams["expanded"])) {
            expanded.setSelected(true);
        }
        if(queryParams["hashes"]) {
            let input = queryParams["hashes"].split(",").join("\n");
            if(input) {
                hashInput.val(input);
                btnSubmit.click();
            }
        }
    }

    function updateExtendedView() {
        let matchCounts = $(".match-count");
        console.log(matchCounts);
        for(var i=0; i<matchCounts.length; i++) {
            let matchCount = $(matchCounts[i]);
            matchCount.text((extended.isSelected() ? matchCount.attr("data-total-extended") : matchCount.attr("data-total")) + " matches");

            let tbody = $("#"+matchCount.attr("for"));
            let extendedResults = tbody.find('[data-extended="true"]');
            if(extended.isSelected()) {
                extendedResults.show();
            } else {
                extendedResults.hide();
            }
        }
    }

    module.init = function () {
        loader = new Loader();
        btnSubmit = $("#submit");
        results = $(".results");
        hashInput = $("#hashes");
        btnShare = $("#share");
        extended = new CheckBox("#extended");
        expanded = new CheckBox("#expanded");

        extended.element.change(function() {
            updateExtendedView();
        });

        $.ajax({
            dataType: 'json',
            url: './data/hash_definitions.json'
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
                tempid++;
                const template = `
<div class="input-group">
    <div class="input-group-prepend">
        <button class="btn btn-primary" type="button" data-toggle="collapse" 
            data-target=".multi-collapse-${tempid}" aria-controls="collapse1-${tempid} collapse2-${tempid}">
            Show matches for:
        </button>
    </div>
    <input type="text" class="form-control"
           id="inlineFormInputGroup" value="${encodeURI(hash.value)}" readonly>
</div>
<div class="collapse multi-collapse-${tempid} ${expanded.isSelected() ? '' : 'show'}" id="collapse1-${tempid}">
    <div class="alert ${hash.matches.length > 0 ? 'alert-success' : 'alert-light'} match-count" role="alert" align="CENTER"
        for="tbody-${tempid}"
        data-total="${hash.matches.filter(match => match.extended === false).length}" data-total-extended="${hash.matches.length}">
        $1 matches
    </div>
    <hr>
</div>
<div class="collapse multi-collapse-${tempid} table-responsive ${expanded.isSelected() ? 'show' : ''}" id="collapse2-${tempid}">
    <table class="table" style="margin-top: 16px;">
        <thead class="thead-dark">
            <tr>
                <th scope="col">Match</th>
                <th scope="col">Hashcat</th>
                <th scope="col">JohnTheRipper</th>
            </tr>
        </thead>
        <tbody id="tbody-${tempid}">
            ${hash.matches.map(match => `<tr data-extended="${match.extended}"><td>${match.name}</td><td>${match.hashcat != null ? match.hashcat : ''}</td><td>${match.john != null ? match.john : ''}</td></tr>`).join('')}
        </tbody>
    </table>
</div>
`;
                return template;
            }

            let hashes = hashInput.val().split("\n");
            let resultList = [];
            hashes.forEach(hash => {
                let isEmpty = hash.trim() === '';
                if(!isEmpty && $.inArray(hash, listed) === -1) {
                    listed.push(hash);
                    hash = {
                        value: hash,
                        matches: []
                    };
                    hashDefs.forEach(def => {
                        var regex = new RegExp(def.regex, 'i')
                        if(decodeURI(hash.value).match(regex)) {
                            def.modes.forEach(def => {
                                hash.matches.push(def);
                            });
                        }
                    });
                    resultList.push(hash);
                }
            });
            loader.hide();
            resultList.forEach(result => {
                btnShare.before(toHtml(result));
                updateExtendedView();
                btnShare.attr("disabled", false);
            });
        } else {
            console.log("Definitions not loaded.");
        }
    };
    module.copyShareURL = function () {
        function textToClipboard (text) {
            var dummy = document.createElement("textarea");
            document.body.appendChild(dummy);
            dummy.value = text;
            dummy.select();
            document.execCommand("copy");
            document.body.removeChild(dummy);
        }
        let location = window.location;
        let shareURL = location.origin+location.pathname;

        shareURL += '?hashes=';
        shareURL += listed.map(hash => encodeURI(hash)).join(',');
        if(extended.isSelected()) {
            shareURL += "&extended=true";
        }
        if(expanded.isSelected()) {
            shareURL += "&expanded=true";
        }

        textToClipboard(shareURL);
    };
    return module;
}());
$(document).ready(function () {
    hashID.init();
});