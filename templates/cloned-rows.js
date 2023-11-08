var $new1 = $(".cloned-row:first").clone(true).insertAfter(".cloned-row:last");
    $new1.find('input[name="item_desc1[]"]').val()
    $new1.find('input[name="item_price1[]"]').val()
    $new1.find('input[name="item_quant1[]"]').val()
    $new1.find('input[name="amount1[]"]').val()
    
{% for item in found_invoice_items %}
<input type="hidden" name="item_desc1[]" value="{{ item.item_desc }}">
<input type="hidden" name="item_price1[]" value="{{ item.item_price }}">
<input type="hidden" name="item_quant1[]" value="{{ item.item_quant }}">
<input type="hidden" name="amount1[]" value="{{ item.amount }}">
<input type="hidden" name="counter" value="{{ loop.index }}">
{% endfor %}

 var item_desc = [];
   for (i = 0, i < counter, i++){
   item_desc[i] = ('input[name="item_desc1[i]"]').val();
   alert(item_desc[i]);
   }
   
$('form').find('.row').each(function() {
        var $this = $(this);
    $this = $(".cloned-row:first").clone(true).insertAfter(".cloned-row:last");
    $this.find('input[name="item_desc[]"]').val(item_desc);
    $this.find('input[name="item_price[]"]').val();
    $this.find('input[name="item_quant[]"]').val();
    $this.find('input[name="amount[]"]').val();
    });
    
for (var i = 0, i < counter, i++) {
    $new1 = $(".cloned-row:first").clone(true).insertAfter(".cloned-row:last");
    $new1.find('input[name="item_desc[]"]').val(('input[name="item_desc1[i]"]').val());
    $new1.find('input[name="item_price[]"]').val(('input[name="item_price1[i]"]').val());
    $new1.find('input[name="item_quant[]"]').val(('input[name="item_quant1[i]"]').val());
    $new1.find('input[name="amount[]"]').val(('input[name="amount1[i]"]').val());
    }
    
    
var highest = -Infinity;
  var item_desc = [];
  var item_price = [];
  var item_quant = [];
  var amount = [];
  
    $('input[name="counter[]"').each(function() {
    
    highest = Math.max(highest, parseFloat(this.value));
    });
    alert(highest);
    
    //var $new1 = $(".cloned-row:first").clone(true).insertAfter(".cloned-row:last");
    $('input[name="item_desc1[]"').each(function() {
    item_desc = $(this).val();
    });
    
    $('input[name="item_price1[]"').each(function() {
    item_price = $(this).val();
    });
    
    
    $('input[name="item_quant1[]"').each(function() {
    item_quant = $(this).val();
    });
    
    
    $('input[name="amount1[]"').each(function() {
    amount = $(this).val();
    });
    
    
    alert(item_desc);
    alert(item_price);
    alert(item_quant);
    alert(amount);
    
    