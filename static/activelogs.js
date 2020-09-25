var start_id = 0;

(function auto_update(){
    $.ajaxSetup({
      headers: { "X-CSRFToken": csrf_token }
    });
    $.ajax({
        type: "POST",
        url: "/activelogs",
        data: JSON.stringify({"id":start_id}),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        success: function (data) {
            var box = $(".activelogs");
            if (start_id == data["id"] || data.id == 0 ){
                box.scrollTop(box[0].scrollHeight - box.height());
            }
            else {
                box.val(box.val() + "\n" + data.logs);
                start_id = data.id
                Success = true;
                box.scrollTop(box[0].scrollHeight - box.height());
            }
        },
        error: function (data) {
            Success = false;
        }
    });

    setTimeout(auto_update, 1000)
})();