$(".col-status").each(function() {
	if ($(this).text().indexOf('wait') >= 0){$(this).closest("tr").attr("class","light_yellow");}
	else if ($(this).text().indexOf('done') >= 0){$(this).closest("tr").attr("class","light_green");}
	else if ($(this).text().indexOf('work') >= 0){$(this).closest("tr").attr("class","light_blue");}
	else if ($(this).text().indexOf('dumy') >= 0){$(this).closest("tr").attr("class","light_red");}
})