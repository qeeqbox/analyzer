$(".col-status").each(function() {
	if ($(this).text().indexOf('wait') >= 0){$(this).closest("tr").attr("class","light_yellow");}
	else if ($(this).text().indexOf('done') >= 0){$(this).closest("tr").attr("class","light_green");}
	else if ($(this).text().indexOf('work') >= 0){$(this).closest("tr").attr("class","light_blue");}
	else if ($(this).text().indexOf('dumy') >= 0){$(this).closest("tr").attr("class","light_red");}
})

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