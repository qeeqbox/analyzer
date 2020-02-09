(function auto_update(){
    var arr = [];
    $(".table tr").each(function() {
        arr.push(this.id);
    });
    $.ajaxSetup({
      headers: { "X-CSRFToken": csrf_token }
    });
    $.ajax({
        type: "POST",
        url: "/dbinfo",
        data: JSON.stringify(arr),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        success: function (items) {
          for (var i in items) {
           for (var ii in items[i]) {
            if (typeof items[i][ii]==='object'){$("#"+i+ii).text(JSON.stringify(items[i][ii]).split(",").join(", "));}
            else{$("#"+i+ii).text(items[i][ii]);}
            }
          }
            Success = true;
        },
        error: function (data) {
            Success = false;
        }
    });

    $(".col-status").each(function() {
      if ($(this).text().indexOf('wait') >= 0){$(this).closest("tr").attr("class","light_yellow");}
      else if ($(this).text().indexOf('done') >= 0){$(this).closest("tr").attr("class","light_green");}
      else if ($(this).text().indexOf('work') >= 0){$(this).closest("tr").attr("class","light_blue");}
      else if ($(this).text().indexOf('dumy') >= 0){$(this).closest("tr").attr("class","light_red");}
    })

    setTimeout(auto_update, 1500)
})();

$('#settings').click(function() {
  maxw = $(".wrapper-col-sidebar").css("max-width");
  if (maxw == "150px") {
    $(".wrapper-col-sidebar").css({
      "max-width": "48px"
    });
    $(".wrapper-col-sidebar .nav-link span").hide();
    $(".wrapper-col-sidebar .nav-link").show();

  } else if (maxw == "48px") {
    $(".wrapper-col-sidebar").css({
      "max-width": "0px"
    });
    $(".wrapper-col-sidebar .nav-link").hide();

  } else {
    $(".wrapper-col-sidebar").css({
      "max-width": "150px"
    });
    $(".wrapper-col-sidebar .nav-link span").show();
    $(".wrapper-col-sidebar .nav-link").show();

    //fix span item not being showing when resize screen
    $(".wrapper-col-sidebar .nav-link span").css({
      "opacity": "1"
    });
  }
});

$(".wrapper-col-sidebar ul li a").on("click", function() {
  $(".wrapper-col-sidebar ul li a").removeClass('active');
  $(this).addClass('active');
});
