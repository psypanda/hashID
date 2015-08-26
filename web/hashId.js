hashTypes = getHashTypes();

$('.inputHash').on('input', function() {
    if (!$('.inputHash').val()) {
        $('h1').text("Enter a hash!");
        $('.output').slideUp();
        $('body').css('background-color', '#78909C');
    } else {
        var matches = findMatches($('.inputHash').val());
        if (matches.length > 0) {
            $('h1').text("Matches Found!");
            $('.output').slideDown();
            $('.output').html(matches.toString().replace(/,/g,"<br />"));
            $('body').css('background-color', '#66BB6A');
        } else {
            $('h1').text("No matches.");
            $('.output').slideUp();
            $('body').css('background-color', '#EF5350');
        }
    }
});

function findMatches(inputHash) {
    var ret = new Array();
    $.each(hashTypes, function() {
        if (inputHash.match(this.regex)){
            $.each(this.modes, function() {
                 ret.push(this.name);
            });
        };
    });
    return ret;
}

function getHashTypes() {
    var ret = [];
    $.getJSON("https://raw.githubusercontent.com/psypanda/hashID/master/prototypes.json", function(json) {
    // Hard link to github due to Cross Origin Same Protocol requirement.
    // If hosted on http server this can be relative ("../prototypes.js")
        $.each(json, function() {
            ret.push(this);
        });
    });
    return ret;
}