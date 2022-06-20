/**
 * hashID (web)
 *
 * Identify hashes in the browser, based on the psypanda/hashID python script.
 *
 * @requires hash_definitions.json
 * @requires jquery
 * @author mattwright324
 */
const hashID = (function () {
    const elements = {};
    const controls = {};
    const tableSettings = {
        columnDefs: [{
            defaultContent: "",
            targets: "_all"
        }, {
            width: "100%",
            targets: 0
        },{
            className: "dt-nowrap",
            targets: [1, 2]
        }],
        lengthMenu: [[10, 25, 50, 100, 250, -1], [10, 25, 50, 100, 250, "All"]],
        pageLength: -1,
        deferRender: true,
        bDeferRender: true
    };

    let hashDefs = {};
    let defsLoaded = false;
    let tempid = 0;

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
            if (input) {
                controls.hashInput.val(input);
                controls.btnSubmit.click();
            }
        }
    }

    const internal = {
        init: function () {
            controls.btnSubmit = $("#submit");
            elements.results = $("#results");
            elements.nothing = $("#nothing");
            controls.hashInput = $("#hashes");
            controls.hashInput.val([
                'plaintext', // not a hash
                '48c/R8JAv757A', // descrypt
                'd41d8cd98f00b204e9800998ecf8427e', // MD5
                'b89eaac7e61417341b710b727768294d0e6a277b', // SHA1
                '8743b52063cd8409', // Half MD5,
            ].join('\n'))
            controls.btnShare = $("#share");
            controls.typesTable = $("#typesTable").DataTable(tableSettings);

            $.ajax({
                dataType: 'json',
                url: './data/hash_definitions.json'
            }).done(function (res) {
                console.log('Loaded hash definitions')
                console.log(res);

                hashDefs = res;
                controls.btnSubmit.attr("disabled", false);
                defsLoaded = true;
                loadFromURL();
            }).fail(function (err) {
                console.error(err);

                elements.nothing.hide();
                elements.results.append("<div class='alert alert-danger'>Could not load hash definitions. Check browser console for error(s).</div>")
            });
        }
    }

    $(document).ready(internal.init);

    return {
        submit: function () {
            elements.results.html('');
            if (!defsLoaded) {
                console.error("Definitions not loaded, cannot identify.");
                return;
            }

            elements.nothing.hide();

            function toHtml(result) {
                tempid++;

                const hasResults = result.matches.length > 0;
                const template = `
<div class="card border-${hasResults ? 'success' : 'secondary'} mb-15">
    <div class="card-header">
        <h5 class="match-count text-${hasResults ? 'success' : 'secondary'}">${result.matches.length} match(es) found</h5>
        <input type="text" class="form-control result-hash" value="${encodeURI(result.value)}" readonly>
    </div>
    <div class="card-body"${hasResults ? '' : ' hidden'}>
        <table class="table" style="margin-top: 16px;">
            <thead class="thead-dark">
                <tr>
                    <th scope="col">Match</th>
                    <th scope="col">hashcat</th>
                    <th scope="col">John</th>
                </tr>
            </thead>
            <tbody id="tbody-${tempid}">
                ${result.matches.map(match => `<tr data-extended="${match.extended}"><td>${match.name}</td><td>${match.hashcat != null ? match.hashcat : ''}</td><td>${match.john != null ? match.john : ''}</td></tr>`).join('')}
            </tbody>
        </table>
    </div>
</div>
`;
                return template;
            }

            let hashes = controls.hashInput.val().replace(/[ \t]/g, '').split(/[\r\n]+/g);
            let resultList = [];
            hashes.forEach(hash => {
                let isEmpty = hash.trim() === '';
                if (!isEmpty) {
                    const result = {
                        value: hash,
                        matches: []
                    };
                    hashDefs.forEach(def => {
                        var regex = new RegExp(def.regex, 'i')
                        if (decodeURI(result.value).match(regex)) {
                            def.modes.forEach(def => {
                                result.matches.push(def);
                            });
                        }
                    });
                    resultList.push(result);
                }
            });
            resultList.forEach(result => {
                elements.results.append(toHtml(result));
                controls.btnShare.attr("disabled", false);
            });

            $("table").DataTable($.extend(tableSettings, {
                searching: false,
                paging: false
            }));
        },

        copyShareURL: function () {
            function textToClipboard(text) {
                var dummy = document.createElement("textarea");
                document.body.appendChild(dummy);
                dummy.value = text;
                dummy.select();
                document.execCommand("copy");
                document.body.removeChild(dummy);
            }

            let location = window.location;
            let shareURL = location.origin + location.pathname;

            shareURL += '?hashes=';
            shareURL += listed.map(hash => encodeURI(hash)).join(',');
            if (extended.isSelected()) {
                shareURL += "&extended=true";
            }
            if (expanded.isSelected()) {
                shareURL += "&expanded=true";
            }

            textToClipboard(shareURL);
        }
    };
}());
